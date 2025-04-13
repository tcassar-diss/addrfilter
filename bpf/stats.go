package bpf

import (
	"errors"
	"fmt"
)

var (
	ErrCfgInvalid             = errors.New("invalid config")
	ErrInvalidSyscallNr       = errors.New("invalid syscall number")
	ErrFilenameMarshalFailed  = errors.New("failed to marshal filename")
	ErrBadLibcRange           = errors.New("nonsensical libc range given")
	ErrWhitelistAlreadyExists = errors.New("whitelist already exists")
)

type Stats struct {
	GetCurrentTaskFailed uint64
	TPEntered            uint64
	GetProfilerFailed    uint64
	IgnorePID            uint64
	ReadPIDFailed        uint64
	ReadPPIDFailed       uint64
	FollowForkFailed     uint64
	LibcNotLoaded        uint64
	StackDebugEmpty      uint64
	GetStackFailed       uint64
	CallsiteLibc         uint64
	StackTooShort        uint64
	NoRPMapping          uint64
	RPNullAfterMap       uint64
	FilenameTooLong      uint64
	FindVMAFailed        uint64
	NoBackingVMA         uint64
	WhitelistMissing     uint64
	SyscallBlocked       uint64
	SendSignalFailed     uint64
}

type Stacktrace struct {
	Stack        [32]uint64
	FramesWalked int32
	CallSite     uint64
}

// WarnMode specifies what action the filter should take when a blacklisted syscall is detected
// (can't be publicly autogenerated).
type WarnMode string

var (
	// KillPID specifies that only the "malicious" PID is killed when a disallowed syscall happens.
	KillPID WarnMode = "kill-pid"
	// KillAll specifies that all PIDs being traced are killed when a disallowed syscall happens.
	KillAll WarnMode = "kill-all"
	// Warn will simply warn userspace when a disallowed syscall happens - nothing is killed.
	Warn WarnMode = "warn"
)

func StrToWarnMode(s string) (WarnMode, error) {
	switch s {
	case string(KillPID):
		return KillPID, nil
	case string(KillAll):
		return KillAll, nil
	case string(Warn):
		return Warn, nil
	default:
	}

	return "", fmt.Errorf("%w: unrecognised warn mode", ErrCfgInvalid)
}
