package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// apkVersion is an Alpine package version: numbers separated by dots, an
// optional letter, any number of suffixes (_alpha2, _p1, ...), and a
// revision (-r3), as apk-tools defines it.
var apkVersion = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)*)([a-z])?((?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)[0-9]*)*)(?:-r([0-9]+))?$`)

var apkSuffix = regexp.MustCompile(`_(alpha|beta|pre|rc|cvs|svn|git|hg|p)([0-9]*)`)

// apkSuffixOrder ranks suffixes: pre-releases sort before the plain
// version, and the rest after it.
var apkSuffixOrder = map[string]int{"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "": 0, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}

type apkParts struct {
	numbers  []string
	letter   string
	suffixes [][2]string
	revision int
}

func parseAPK(value string) (apkParts, error) {
	match := apkVersion.FindStringSubmatch(strings.TrimSpace(value))
	if match == nil {
		return apkParts{}, fmt.Errorf("invalid Alpine package version %q", value)
	}
	parts := apkParts{numbers: strings.Split(match[1], "."), letter: match[2]}
	for _, suffix := range apkSuffix.FindAllStringSubmatch(match[3], -1) {
		parts.suffixes = append(parts.suffixes, [2]string{suffix[1], suffix[2]})
	}
	if match[4] != "" {
		parts.revision, _ = strconv.Atoi(match[4])
	}
	return parts, nil
}

// APK compares two Alpine package versions the way apk does: -1, 0 or 1.
func APK(left, right string) (int, error) {
	a, err := parseAPK(left)
	if err != nil {
		return 0, err
	}
	b, err := parseAPK(right)
	if err != nil {
		return 0, err
	}
	for index := 0; index < len(a.numbers) || index < len(b.numbers); index++ {
		if index >= len(a.numbers) {
			return -1, nil
		}
		if index >= len(b.numbers) {
			return 1, nil
		}
		if order := compareAPKNumber(a.numbers[index], b.numbers[index], index > 0); order != 0 {
			return order, nil
		}
	}
	if a.letter != b.letter {
		if a.letter == "" {
			return -1, nil
		}
		if b.letter == "" {
			return 1, nil
		}
		return sign(strings.Compare(a.letter, b.letter)), nil
	}
	for index := 0; index < len(a.suffixes) || index < len(b.suffixes); index++ {
		var sa, sb [2]string
		if index < len(a.suffixes) {
			sa = a.suffixes[index]
		}
		if index < len(b.suffixes) {
			sb = b.suffixes[index]
		}
		if order := sign(apkSuffixOrder[sa[0]] - apkSuffixOrder[sb[0]]); order != 0 {
			return order, nil
		}
		na, _ := strconv.Atoi(sa[1])
		nb, _ := strconv.Atoi(sb[1])
		if na != nb {
			return sign(na - nb), nil
		}
	}
	return sign(a.revision - b.revision), nil
}

// compareAPKNumber compares one dotted component. After the first, a
// component with a leading zero is a fraction, compared digit by digit, as
// apk does: 1.01 < 1.1, and 1.001 < 1.01.
func compareAPKNumber(left, right string, fraction bool) int {
	if fraction && (strings.HasPrefix(left, "0") || strings.HasPrefix(right, "0")) {
		return sign(strings.Compare(strings.TrimRight(left, "0"), strings.TrimRight(right, "0")))
	}
	left, right = strings.TrimLeft(left, "0"), strings.TrimLeft(right, "0")
	if len(left) != len(right) {
		return sign(len(left) - len(right))
	}
	return sign(strings.Compare(left, right))
}
