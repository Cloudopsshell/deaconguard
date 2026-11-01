package live

import (
	"bytes"
	"debug/elf"
	_ "embed"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// watchObject is internal/live/bpf/watch.c compiled by scripts/build-bpf.sh.
//
//go:embed watch.o
var watchObject []byte

// MapSpec is a map the watchers use, from the object's "maps" section.
type MapSpec struct {
	Name       string
	Type       uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
}

// ProgramSpec is one watcher: the tracepoint it attaches to, its
// instructions, and where in them it refers to a map.
type ProgramSpec struct {
	Category, Event string
	Instructions    []byte
	// MapRefs maps an instruction's index to the map it loads.
	MapRefs map[int]string
}

// Object is the parsed watchers.
type Object struct {
	License  string
	Maps     []MapSpec
	Programs []ProgramSpec
}

const (
	instructionSize = 8
	// opLoadImm64 is BPF_LD | BPF_IMM | BPF_DW, the two-slot instruction a
	// map reference compiles to.
	opLoadImm64 = 0x18
	// relocation64 is R_BPF_64_64, the only relocation the loader accepts.
	relocation64 = 1
	mapSpecSize  = 20
)

// ParseObject reads the watchers' ELF object. It accepts only what
// watch.c produces: programs in "tp/CATEGORY/EVENT" sections, maps in
// "maps", and relocations that point instructions at those maps.
func ParseObject(data []byte) (*Object, error) {
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("read the watchers: %w", err)
	}
	if file.Machine != elf.EM_BPF || file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB {
		return nil, fmt.Errorf("the watchers are not a little-endian BPF object")
	}
	object := &Object{}
	symbols, err := file.Symbols()
	if err != nil {
		return nil, fmt.Errorf("read the watchers' symbols: %w", err)
	}
	mapsIndex := -1
	for index, section := range file.Sections {
		switch section.Name {
		case "license":
			contents, err := section.Data()
			if err != nil {
				return nil, err
			}
			object.License = strings.TrimRight(string(contents), "\x00")
		case "maps":
			mapsIndex = index
		}
	}
	if object.License == "" {
		return nil, fmt.Errorf("the watchers have no license section")
	}
	byOffset := map[uint64]string{}
	if mapsIndex >= 0 {
		contents, err := file.Sections[mapsIndex].Data()
		if err != nil {
			return nil, err
		}
		for _, symbol := range symbols {
			if int(symbol.Section) != mapsIndex || elf.ST_TYPE(symbol.Info) != elf.STT_OBJECT {
				continue
			}
			if symbol.Value+mapSpecSize > uint64(len(contents)) {
				return nil, fmt.Errorf("map %s lies outside the maps section", symbol.Name)
			}
			raw := contents[symbol.Value:]
			spec := MapSpec{
				Name:       symbol.Name,
				Type:       binary.LittleEndian.Uint32(raw[0:]),
				KeySize:    binary.LittleEndian.Uint32(raw[4:]),
				ValueSize:  binary.LittleEndian.Uint32(raw[8:]),
				MaxEntries: binary.LittleEndian.Uint32(raw[12:]),
				Flags:      binary.LittleEndian.Uint32(raw[16:]),
			}
			object.Maps = append(object.Maps, spec)
			byOffset[symbol.Value] = symbol.Name
		}
		sort.Slice(object.Maps, func(i, j int) bool { return object.Maps[i].Name < object.Maps[j].Name })
	}
	for index, section := range file.Sections {
		name, ok := strings.CutPrefix(section.Name, "tp/")
		if !ok || section.Type != elf.SHT_PROGBITS {
			continue
		}
		category, event, ok := strings.Cut(name, "/")
		if !ok || category == "" || event == "" {
			return nil, fmt.Errorf("program section %s isn't tp/CATEGORY/EVENT", section.Name)
		}
		instructions, err := section.Data()
		if err != nil {
			return nil, err
		}
		if len(instructions) == 0 || len(instructions)%instructionSize != 0 {
			return nil, fmt.Errorf("program %s has a partial instruction", section.Name)
		}
		program := ProgramSpec{Category: category, Event: event, Instructions: instructions, MapRefs: map[int]string{}}
		for _, relocations := range file.Sections {
			if relocations.Type != elf.SHT_REL || int(relocations.Info) != index {
				continue
			}
			contents, err := relocations.Data()
			if err != nil {
				return nil, err
			}
			for at := 0; at+16 <= len(contents); at += 16 {
				offset := binary.LittleEndian.Uint64(contents[at:])
				info := binary.LittleEndian.Uint64(contents[at+8:])
				symbolIndex, kind := int(info>>32), uint32(info)
				if kind != relocation64 || symbolIndex < 1 || symbolIndex > len(symbols) {
					return nil, fmt.Errorf("program %s has an unsupported relocation", section.Name)
				}
				symbol := symbols[symbolIndex-1]
				target, isMap := byOffset[symbol.Value]
				if int(symbol.Section) != mapsIndex || !isMap {
					return nil, fmt.Errorf("program %s refers to %s, which isn't a map", section.Name, symbol.Name)
				}
				slot := int(offset / instructionSize)
				if offset%instructionSize != 0 || (slot+2)*instructionSize > len(instructions) || instructions[slot*instructionSize] != opLoadImm64 {
					return nil, fmt.Errorf("program %s refers to map %s from an unexpected instruction", section.Name, target)
				}
				program.MapRefs[slot] = target
			}
		}
		object.Programs = append(object.Programs, program)
	}
	if len(object.Programs) == 0 {
		return nil, fmt.Errorf("the watchers have no programs")
	}
	return object, nil
}

// Linked returns program's instructions with each map reference pointing
// at the map's file descriptor, as the kernel expects: the instruction's
// source register set to BPF_PSEUDO_MAP_FD and its immediate to the fd.
func (program ProgramSpec) Linked(fds map[string]int) ([]byte, error) {
	instructions := append([]byte(nil), program.Instructions...)
	for slot, name := range program.MapRefs {
		fd, ok := fds[name]
		if !ok {
			return nil, fmt.Errorf("map %s wasn't created", name)
		}
		at := slot * instructionSize
		const pseudoMapFD = 1
		instructions[at+1] = instructions[at+1]&0x0f | pseudoMapFD<<4
		binary.LittleEndian.PutUint32(instructions[at+4:], uint32(fd))
	}
	return instructions, nil
}
