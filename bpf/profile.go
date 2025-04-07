package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
)

/* profile is used to pull profiling data from BPF
*
* make sure that the BPF program is compiled with the #PROFILE macro defined,
* otherwise this poor ringbuffer will never read anything
 */

// Profiler serves as the frontend interface to the BPF program's profiling
// code.
//
// Profiler will listen to the profiling ringbuffer and write stats to wherever
// specified in CSV format.
type Profiler struct {
	logger      *zap.SugaredLogger
	profRingbuf *ebpf.Map
	outputDest  csv.Writer
}

func NewProfiler(logger *zap.SugaredLogger, profileMap *ebpf.Map, outputDest io.Writer) (*Profiler, error) {
	csvWriter := csv.NewWriter(outputDest)

	return &Profiler{
		profRingbuf: profileMap,
		logger:      logger,
		outputDest:  *csvWriter,
	}, nil
}

// Monitor writes profiling information to the output dest as profiles come in.
//
// Calls to monitor are blocking
func (p *Profiler) Monitor(ctx context.Context) error {
	profChan := make(chan addrfilterProfileInfo, 64)
	errChan := make(chan error, 1)

	p.outputDest.Write([]string{
		"get-pid",
		"apply-filter",
		"find-syscall-site",
		"assign-filename",
		"assoc-whitelist",
		"perform-filtering",
	})
	defer p.profRingbuf.Close()

	go p.listen(profChan, errChan)
	go p.processSamples(ctx, profChan, errChan)

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errChan:
			return err
		}
	}
}

func (p *Profiler) listen(
	profChan chan<- addrfilterProfileInfo,
	errChan chan<- error,
) {
	p.logger.Info("profiler listening")
	defer close(profChan)
	defer close(errChan)

	rd, err := ringbuf.NewReader(p.profRingbuf)
	if err != nil {
		errChan <- fmt.Errorf("failed to get reader to ringbuf: %w", err)
	}
	defer rd.Close()

	for {
		record, err := rd.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			p.logger.Info("profile ringbuf closed")
			return
		} else if err != nil {
			errChan <- fmt.Errorf("failed to read from ringbuf: %w", err)
		}

		var sample addrfilterProfileInfo

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &sample); err != nil {
			errChan <- fmt.Errorf("failed to read from ringbuf: %w", err)
		}

		profChan <- sample
	}
}

func (p *Profiler) processSamples(
	ctx context.Context,
	profChan <-chan addrfilterProfileInfo,
	errChan chan<- error,
) {
	defer p.outputDest.Flush()

	var sample addrfilterProfileInfo
	for {
		select {
		case <-ctx.Done():
			return
		case sample = <-profChan:
		}

		// convert sample from series of timestamps into durations
		durations := []int{
			int(sample.GetPid - sample.Start),
			int(sample.ApplyFilter - sample.GetPid),
			int(sample.FindSyscallSite - sample.ApplyFilter),
			int(sample.AssignFilename - sample.FindSyscallSite),
			int(sample.AssocWhitelist - sample.AssignFilename),
			int(sample.End - sample.AssocWhitelist),
		}

		// when syscalls aren't blocked, they return early.
		// this makes timestamp durations look massive, so zero
		// out any fields which are larger than the entrance timestamp
		for i, d := range durations {
			if d < 0 {
				durations[i] = 0
			}
		}

		durStrs := make([]string, 0, 5)

		for _, d := range durations {
			durStrs = append(durStrs, strconv.Itoa(d))
		}

		if err := p.outputDest.Write(durStrs); err != nil {
			errChan <- fmt.Errorf("failed to write profile to output: %w", err)
			return
		}
	}
}
