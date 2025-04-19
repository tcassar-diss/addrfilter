package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/tcassar-diss/addrfilter/frontend"
)

var Usage = "syso-wl-conv syso.json ./path/to/whitelist.toml"

var ErrInvalidArgs = errors.New("invalid arguments")

type args struct {
	sysoWlPath string
	tomlWlPath string
}

func NoErr(err error, msg *string) {
	if err != nil {
		log.Fatalf("error converting syso whitelist to toml! %v\n", err)
	}
}

func parseArgs(argv []string) (*args, error) {
	if len(argv) != 3 {
		return nil, fmt.Errorf("%w: expected 2 args, got %d", ErrInvalidArgs, len(argv)-1)
	}

	parsed := &args{
		sysoWlPath: argv[1],
		tomlWlPath: argv[2],
	}

	if _, err := os.Stat(parsed.sysoWlPath); err != nil {
		return nil, fmt.Errorf("problem with syso whitelist: %w", err)
	}

	return parsed, nil
}

func main() {
	args, err := parseArgs(os.Args)
	NoErr(err, &Usage)

	whitelist, err := frontend.ParseSysoWhitelists(args.sysoWlPath)
	NoErr(err, nil)

	f, err := os.Create(args.tomlWlPath)
	NoErr(err, nil)

	err = frontend.MarshalTOMLWhitelists(f, whitelist)
	NoErr(err, nil)
}
