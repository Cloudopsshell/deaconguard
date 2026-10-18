package containers

import (
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

// RPM header tags DeaconGuard reads.
const (
	tagName      = 1000
	tagVersion   = 1001
	tagRelease   = 1002
	tagEpoch     = 1003
	tagArch      = 1022
	tagSourceRPM = 1044

	typeInt32  = 4
	typeString = 6
)

// rpmQueryFromSQLite reads the packages of an RPM database in SQLite format
// (rpmdb.sqlite, used by RHEL 9 and later, Fedora and Amazon Linux 2023),
// copied out of a container, and writes them in the format of the rpm query
// the agent runs on hosts. Nothing from the container is executed: the
// database is opened read-only from a private copy.
func rpmQueryFromSQLite(data []byte) (string, error) {
	dir, err := os.MkdirTemp("", "deaconguard-rpmdb-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "rpmdb.sqlite")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", err
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return "", err
	}
	defer db.Close()
	rows, err := db.Query("SELECT blob FROM Packages")
	if err != nil {
		return "", fmt.Errorf("read the RPM database: %w", err)
	}
	defer rows.Close()
	var out strings.Builder
	for rows.Next() {
		var blob []byte
		if err := rows.Scan(&blob); err != nil {
			return "", err
		}
		header, err := parseHeader(blob)
		if err != nil {
			continue
		}
		name := header.strings[tagName]
		if name == "" || name == "gpg-pubkey" || header.strings[tagVersion] == "" {
			continue
		}
		epoch := "0"
		if value, ok := header.ints[tagEpoch]; ok {
			epoch = fmt.Sprint(value)
		}
		fmt.Fprintf(&out, "%s\t%s\t%s\t%s\t%s\t%s\t(none)\n", name, epoch, header.strings[tagVersion], header.strings[tagRelease],
			header.strings[tagSourceRPM], header.strings[tagArch])
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if out.Len() == 0 {
		return "", errors.New("the RPM database lists no packages")
	}
	return out.String(), nil
}

type rpmHeader struct {
	strings map[int]string
	ints    map[int]int64
}

// parseHeader reads an RPM header as rpmdb stores it: the number of index
// entries and the data size (big-endian), the entries (tag, type, offset,
// count), then the data.
func parseHeader(blob []byte) (rpmHeader, error) {
	header := rpmHeader{strings: map[int]string{}, ints: map[int]int64{}}
	if len(blob) < 8 {
		return header, errors.New("short header")
	}
	count := int(binary.BigEndian.Uint32(blob[0:4]))
	size := int(binary.BigEndian.Uint32(blob[4:8]))
	start := 8 + 16*count
	if count <= 0 || count > 100000 || size < 0 || start+size > len(blob) {
		return header, errors.New("invalid header")
	}
	data := blob[start : start+size]
	for index := 0; index < count; index++ {
		entry := blob[8+16*index : 8+16*index+16]
		tag := int(binary.BigEndian.Uint32(entry[0:4]))
		kind := int(binary.BigEndian.Uint32(entry[4:8]))
		offset := int(binary.BigEndian.Uint32(entry[8:12]))
		if offset < 0 || offset >= len(data) {
			continue
		}
		switch {
		case kind == typeString && (tag == tagName || tag == tagVersion || tag == tagRelease || tag == tagArch || tag == tagSourceRPM):
			end := offset
			for end < len(data) && data[end] != 0 {
				end++
			}
			header.strings[tag] = string(data[offset:end])
		case kind == typeInt32 && tag == tagEpoch && offset+4 <= len(data):
			header.ints[tag] = int64(binary.BigEndian.Uint32(data[offset : offset+4]))
		}
	}
	return header, nil
}
