package bpf

type Stats struct {
	GetCurrentTaskFailed uint64
	TPEntered            uint64
	IgnorePID            uint64
	ReadPIDFailed        uint64
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

// Whitelist associates a filename with a set of allowed syscall numbers
type Whitelist struct {
	Filename string
	Syscalls []int
}
