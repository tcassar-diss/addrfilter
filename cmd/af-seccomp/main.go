// af-seccomp launches a seccomp-filtered application. It takes a **syso**
// whitelist as input and generates a seccomp filter from the union of the
// syscalls present in the syso file.
package main

import (
	"fmt"
	"log"
	"maps"
	"os"

	seccomp "github.com/seccomp/libseccomp-golang"
	"github.com/tcassar-diss/addrfilter/frontend"
)

const Usage = "af-seccomp [syso-whitelist].json /path/to/exec"

type afArgs struct {
	whitelistPath string
	binary        string
	binaryArgs    []string
}

func parseArgs(args []string) (*afArgs, error) {
	if len(os.Args) < 3 {
		return nil, fmt.Errorf("error! expected at least 3 arguments!\n%s", Usage)
	}

	parsedArgs := afArgs{
		whitelistPath: args[1],
		binary:        args[2],
		binaryArgs:    args[3:],
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

func buildFilter(whitelistPath string) (*seccomp.ScmpFilter, error) {
	whitelist, err := parseWhitelist(whitelistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to generate a seccomp whitelist from syso file: %w", err)
	}

	fmt.Printf("%v\n", whitelist)

	return nil, nil
}

func main() {
	args, err := parseArgs(os.Args)
	if err != nil {
		log.Fatalf("failed to parse args: %v", err)
	}

	_, err = buildFilter(args.whitelistPath)
	if err != nil {
		log.Fatalf("failed to build filter: %v", err)
	}
}
