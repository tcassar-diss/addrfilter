package bpf

import "errors"

var (
	ErrInvalidSyscallNr       = errors.New("invalid syscall number")
	ErrFilenameMarshalFailed  = errors.New("failed to marshal filename")
	ErrBadLibcRange           = errors.New("nonsensical libc range given")
	ErrWhitelistAlreadyExists = errors.New("whitelist already exists")
)

type LibcRange struct {
	Start uint64
	End   uint64
}

// NewLibcRange returns a start and end as a LibcRange
func NewLibcRange(start, end uint64) *LibcRange {
	return &LibcRange{
		Start: start,
		End:   end,
	}
}
