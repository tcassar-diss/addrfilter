// af-seccomp launches a seccomp-filtered application. It takes a **syso**
// whitelist as input and generates a seccomp filter from the union of the
// syscalls present in the syso file.
package main

import (
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"os/exec"

	libseccomp "github.com/seccomp/libseccomp-golang"
	"github.com/tcassar-diss/addrfilter/frontend"
)

const Usage = "af-seccomp [syso-whitelist].json /path/to/exec"

var ErrInvalidArgs = errors.New("invalid arguments")

type afArgs struct {
	whitelistPath string
	binary        string
	binaryArgs    []string
}

func parseArgs(args []string) (*afArgs, error) {
	if len(os.Args) < 3 {
		return nil, fmt.Errorf("%w: expected at least 3 arguments", ErrInvalidArgs)
	}

	parsedArgs := afArgs{
		whitelistPath: args[1],
		binary:        args[2],
		binaryArgs:    args[3:],
	}

	if _, err := os.Stat(parsedArgs.binary); err != nil {
		return nil, fmt.Errorf("stat-ing binary failed: %w", err)
	}

	return &parsedArgs, nil
}

func parseWhitelist(whitelistPath string) ([]int, error) {
	soWhitelists, err := frontend.ParseSysoWhitelists(whitelistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse syso whitelist: %w", err)
	}

	scWhitelist := make(map[int]struct{})

	for _, wl := range soWhitelists.NameSyscallMap {
		for _, nr := range wl {
			scWhitelist[int(nr)] = struct{}{}
		}
	}

	whitelist := make([]int, 0, len(scWhitelist))

	for nr := range maps.Keys(scWhitelist) {
		whitelist = append(whitelist, nr)
	}

	return whitelist, nil
}

func initFilter() (*libseccomp.ScmpFilter, error) {
	filter, err := libseccomp.NewFilter(libseccomp.ActKillProcess)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new seccomp filter: %w", err)
	}

	arch, err := libseccomp.GetNativeArch()
	if err != nil {
		return nil, fmt.Errorf("failed to get native arch: %w", err)
	}

	filter.AddArch(arch)

	return filter, nil
}

func buildFilter(whitelistPath string) (*libseccomp.ScmpFilter, error) {
	whitelist, err := parseWhitelist(whitelistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to generate a seccomp whitelist from syso file: %w", err)
	}

	log.Printf("%v\n", whitelist)

	filter, err := initFilter()
	if err != nil {
		return nil, fmt.Errorf("failed to init filter: %w", err)
	}

	for _, nr := range whitelist {
		if err := filter.AddRule(libseccomp.ScmpSyscall(nr), libseccomp.ActTrace); err != nil {
			return nil, fmt.Errorf("failed to add %d to whitelist: %w", nr, err)
		}
	}

	return filter, nil
}

func main() {
	args, err := parseArgs(os.Args)
	if err != nil {
		log.Fatalf("failed to parse args: %v\n", err)
	}

	filter, err := buildFilter(args.whitelistPath)
	if err != nil {
		log.Fatalf("failed to build filter: %v\n", err)
	}

	if err := filter.Load(); err != nil {
		log.Fatalf("failed to load filter to kernel: %v\n", err)
	}

	log.Printf("successfully loaded filter!\n")

	cmd := exec.Command(args.binary, args.binaryArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Fatalf("failed to run binary (%s %v): %v", args.binary, args.binaryArgs, err)
	}
}
