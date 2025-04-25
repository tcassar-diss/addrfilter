package frontend

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"time"

	"go.uber.org/zap"
)

const (
	Retries    = 5
	RetryDelay = 150 * time.Millisecond
)

var ErrFindLibcFailed = errors.New("failed to find libc mapping")

var LibcRegex = regexp.MustCompile(
	`^([a-f0-9]{12})-([a-f0-9]{12})\s[rpxw-]{4}\s[a-f0-9]{8}\s[0-9:]{5}\s[0-9]*\b\s{18}(\S*)libc.so.6$`,
)

type VMRange struct {
	Start uint64
	End   uint64
}

func FindLibc(path string, logger *zap.SugaredLogger) (*VMRange, error) {
	const maxUint = math.MaxUint64

	var libcRange VMRange
	libcRange.Start = maxUint
	libcRange.End = 0

	// for reasons unknown to me, libc takes longer to map into the address
	// space than the other file backed regions hence the retry logic.
	for range Retries {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open %s: %w", path, err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		found := false

		for scanner.Scan() {
			line := scanner.Text()
			if logger != nil {
				logger.Infow("Line read from proc maps", "vm_area", line)
			}
			matches := LibcRegex.FindStringSubmatch(line)
			if matches == nil {
				continue
			}
			found = true

			startAddr, err := strconv.ParseUint(matches[1], 16, 64)
			if err != nil {
				f.Close()
				return nil, fmt.Errorf("invalid start address %q: %w", matches[1], err)
			}
			endAddr, err := strconv.ParseUint(matches[2], 16, 64)
			if err != nil {
				f.Close()
				return nil, fmt.Errorf("invalid end address %q: %w", matches[2], err)
			}

			if startAddr < libcRange.Start {
				libcRange.Start = startAddr
			}
			if endAddr > libcRange.End {
				libcRange.End = endAddr
			}
		}

		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error scanning %s: %w", path, err)
		}

		if found {
			break
		}

		time.Sleep(RetryDelay)
	}

	if libcRange.Start == maxUint || libcRange.End == 0 {
		return nil, fmt.Errorf("%w: libc wasn't matched after %d tries", ErrFindLibcFailed, Retries)
	}
	if libcRange.End <= libcRange.Start {
		return nil, fmt.Errorf("%w: invalid range %#x–%#x", ErrFindLibcFailed, libcRange.Start, libcRange.End)
	}

	return &libcRange, nil
}
