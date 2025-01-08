package bpf

type Stats struct {
	GetCurrentTaskFailed uint64
	TPEntered            uint64
	IgnorePID            uint64
	RingbufReserveFailed uint64
	ReadPIDFailed        uint64
	LibcNotLoaded        uint64
	GetStackFailed       uint64
	CallsiteLibc         uint64
	StackTooShort        uint64
}

type Stacktrace struct {
	Stack        [32]uint64
	FramesWalked int32
	CallSite     uint64
}
