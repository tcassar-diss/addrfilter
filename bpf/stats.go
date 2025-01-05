package bpf

type Stats struct {
	GetCurrentTaskFailed uint64
	TPEntered            uint64
	IgnorePID            uint64
}
