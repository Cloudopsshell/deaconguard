package version

import (
	"fmt"
	"strconv"
	"strings"
)

func Debian(left, right string) (int, error) {
	leftEpoch, leftRest, err := splitDebianVersion(left)
	if err != nil {
		return 0, err
	}
	rightEpoch, rightRest, err := splitDebianVersion(right)
	if err != nil {
		return 0, err
	}
	if leftEpoch != rightEpoch {
		return sign(leftEpoch - rightEpoch), nil
	}
	leftUpstream, leftRevision := splitRevision(leftRest)
	rightUpstream, rightRevision := splitRevision(rightRest)
	if comparison := compareDebianPart(leftUpstream, rightUpstream); comparison != 0 {
		return comparison, nil
	}
	return compareDebianPart(leftRevision, rightRevision), nil
}

func splitRevision(value string) (string, string) {
	index := strings.LastIndexByte(value, '-')
	if index < 0 {
		return value, "0"
	}
	return value[:index], value[index+1:]
}

func splitDebianVersion(value string) (int, string, error) {
	epochText, rest, hasEpoch := strings.Cut(value, ":")
	if !hasEpoch {
		rest = value
		epochText = "0"
	}
	if rest == "" {
		return 0, "", fmt.Errorf("invalid Debian version %q", value)
	}
	epoch, err := strconv.Atoi(epochText)
	if err != nil || epoch < 0 {
		return 0, "", fmt.Errorf("invalid Debian version epoch in %q", value)
	}
	return epoch, rest, nil
}

func compareDebianPart(left, right string) int {
	leftIndex, rightIndex := 0, 0
	for leftIndex < len(left) || rightIndex < len(right) {
		for (leftIndex < len(left) && !isDigit(left[leftIndex])) || (rightIndex < len(right) && !isDigit(right[rightIndex])) {
			var leftChar, rightChar byte
			if leftIndex < len(left) {
				leftChar = left[leftIndex]
			}
			if rightIndex < len(right) {
				rightChar = right[rightIndex]
			}
			if difference := debianOrder(leftChar) - debianOrder(rightChar); difference != 0 {
				return sign(difference)
			}
			if leftChar != 0 {
				leftIndex++
			}
			if rightChar != 0 {
				rightIndex++
			}
		}
		for leftIndex < len(left) && left[leftIndex] == '0' {
			leftIndex++
		}
		for rightIndex < len(right) && right[rightIndex] == '0' {
			rightIndex++
		}
		leftStart, rightStart := leftIndex, rightIndex
		for leftIndex < len(left) && isDigit(left[leftIndex]) {
			leftIndex++
		}
		for rightIndex < len(right) && isDigit(right[rightIndex]) {
			rightIndex++
		}
		leftNumber, rightNumber := left[leftStart:leftIndex], right[rightStart:rightIndex]
		if len(leftNumber) != len(rightNumber) {
			return sign(len(leftNumber) - len(rightNumber))
		}
		if leftNumber != rightNumber {
			if leftNumber > rightNumber {
				return 1
			}
			return -1
		}
	}
	return 0
}

func debianOrder(value byte) int {
	if value == '~' {
		return -1
	}
	if value == 0 {
		return 0
	}
	if value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' {
		return int(value)
	}
	return int(value) + 256
}

func isDigit(value byte) bool { return value >= '0' && value <= '9' }

func sign(value int) int {
	if value < 0 {
		return -1
	}
	if value > 0 {
		return 1
	}
	return 0
}
