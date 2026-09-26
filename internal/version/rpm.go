package version

import (
	"fmt"
	"strconv"
	"strings"
)

func RPM(left, right string) (int, error) {
	leftEpoch, leftEVR, err := splitRpmEpoch(left)
	if err != nil {
		return 0, err
	}
	rightEpoch, rightEVR, err := splitRpmEpoch(right)
	if err != nil {
		return 0, err
	}
	if leftEpoch != rightEpoch {
		return sign(leftEpoch - rightEpoch), nil
	}
	leftVersion, leftRelease, leftHasRelease := strings.Cut(leftEVR, "-")
	rightVersion, rightRelease, rightHasRelease := strings.Cut(rightEVR, "-")
	if comparison := rpmvercmp(leftVersion, rightVersion); comparison != 0 {
		return comparison, nil
	}
	if leftHasRelease && rightHasRelease {
		return rpmvercmp(leftRelease, rightRelease), nil
	}
	if leftHasRelease {
		return 1, nil
	}
	if rightHasRelease {
		return -1, nil
	}
	return 0, nil
}

func splitRpmEpoch(value string) (int, string, error) {
	epochText, evr, hasEpoch := strings.Cut(value, ":")
	if !hasEpoch {
		return 0, value, nil
	}
	epoch, err := strconv.Atoi(epochText)
	if err != nil || epoch < 0 || evr == "" {
		return 0, "", fmt.Errorf("invalid RPM EVR %q", value)
	}
	return epoch, evr, nil
}

func rpmvercmp(left, right string) int {
	leftIndex, rightIndex := 0, 0
	for leftIndex < len(left) || rightIndex < len(right) {
		if leftIndex < len(left) && left[leftIndex] == '~' || rightIndex < len(right) && right[rightIndex] == '~' {
			if leftIndex >= len(left) || left[leftIndex] != '~' {
				return 1
			}
			if rightIndex >= len(right) || right[rightIndex] != '~' {
				return -1
			}
			leftIndex++
			rightIndex++
			continue
		}
		if leftIndex < len(left) && left[leftIndex] == '^' || rightIndex < len(right) && right[rightIndex] == '^' {
			leftCaret := leftIndex < len(left) && left[leftIndex] == '^'
			rightCaret := rightIndex < len(right) && right[rightIndex] == '^'
			if leftCaret && rightIndex >= len(right) {
				return 1
			}
			if rightCaret && leftIndex >= len(left) {
				return -1
			}
			if leftCaret != rightCaret {
				if leftCaret {
					return -1
				}
				return 1
			}
			leftIndex++
			rightIndex++
			continue
		}
		leftIndex = skipSeparators(left, leftIndex)
		rightIndex = skipSeparators(right, rightIndex)
		if leftIndex >= len(left) || rightIndex >= len(right) {
			break
		}
		leftNumeric, rightNumeric := isDigit(left[leftIndex]), isDigit(right[rightIndex])
		leftStart, rightStart := leftIndex, rightIndex
		for leftIndex < len(left) && isDigit(left[leftIndex]) == leftNumeric && isAlphaNum(left[leftIndex]) {
			leftIndex++
		}
		for rightIndex < len(right) && isDigit(right[rightIndex]) == rightNumeric && isAlphaNum(right[rightIndex]) {
			rightIndex++
		}
		leftSegment, rightSegment := left[leftStart:leftIndex], right[rightStart:rightIndex]
		if leftNumeric != rightNumeric {
			if leftNumeric {
				return 1
			}
			return -1
		}
		if leftNumeric {
			leftSegment = strings.TrimLeft(leftSegment, "0")
			rightSegment = strings.TrimLeft(rightSegment, "0")
			if len(leftSegment) != len(rightSegment) {
				return sign(len(leftSegment) - len(rightSegment))
			}
		}
		if leftSegment != rightSegment {
			if leftSegment > rightSegment {
				return 1
			}
			return -1
		}
	}
	if leftIndex >= len(left) && rightIndex >= len(right) {
		return 0
	}
	if leftIndex >= len(left) {
		if rightIndex < len(right) && (right[rightIndex] == '~' || right[rightIndex] == '^') {
			return 1
		}
		return -1
	}
	if rightIndex >= len(right) {
		if leftIndex < len(left) && (left[leftIndex] == '~' || left[leftIndex] == '^') {
			return -1
		}
		return 1
	}
	return 0
}

func skipSeparators(value string, index int) int {
	for index < len(value) && !isAlphaNum(value[index]) && value[index] != '~' && value[index] != '^' {
		index++
	}
	return index
}

func isAlphaNum(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}
