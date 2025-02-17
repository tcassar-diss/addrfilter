package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
)

var ErrFindLibcFailed = errors.New("failed to find libc mapping")

// LibcRegex matches lines in /proc/PID/maps which
//   - Have 64 bit start and end addresses
//   - Contain a file `libc.so.6`; doesn't check preceding filepath
//
// Start range is placed in match group 1, end range in match group 2
var LibcRegex = regexp.MustCompile(
	`^([a-f0-9]{12})-([a-f0-9]{12})\s[rpxw-]{4}\s[a-f0-9]{8}\s[0-9:]{5}\s[0-9]*\b\s{18}(\S*)libc.so.6$`,
)

// VMRange holds the start and end range of a contiguous space in memory
type VMRange struct {
	Start uint64
	End   uint64
}

// FindLibc will find a contiguous range of addresses to which libc is mapped.
//
// it requires path: a path to /proc/PID/maps
func FindLibc(path string) (*VMRange, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer f.Close()

	libcRange := VMRange{
		Start: 1<<64 - 1, // uint64 max
		End:   0,         // uint64 min
	}

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		l := scanner.Text()
		addresses := LibcRegex.FindStringSubmatch(l)

		if addresses == nil {
			continue
		}

		lStart, err := strconv.ParseUint(addresses[1], 16, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to convert lower range to integer: %w", err)
		}

		lEnd, err := strconv.ParseUint(addresses[2], 16, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to convert upper range to integer: %w", err)
		}

		if lStart < libcRange.Start {
			libcRange.Start = lStart
		}

		if libcRange.End < lEnd {
			libcRange.End = lEnd
		}
	}

	if libcRange.Start == 1<<64-1 && libcRange.End == 0 {
		return nil, fmt.Errorf("%w: libc wasn't matched", ErrFindLibcFailed)
	}

	if libcRange.Start == 1<<64-1 {
		return nil, fmt.Errorf("%w: no start range found", ErrFindLibcFailed)
	}

	if libcRange.End == 0 {
		return nil, fmt.Errorf("%w: no end range found", ErrFindLibcFailed)
	}

	if libcRange.End <= libcRange.Start {
		return nil, fmt.Errorf("%w: start and end addresses overlap", ErrFindLibcFailed)
	}

	return &libcRange, nil
}
