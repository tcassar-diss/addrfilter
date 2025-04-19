package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/tcassar-diss/addrfilter/frontend"
)

func main() {
	pid64, err := strconv.ParseInt(os.Args[1], 10, 32)
	if err != nil {
		log.Fatalf("failed to parse PID: %v", err)
	}

	pid := int(pid64)

	addr, err := frontend.FindLibc(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		log.Fatalf("failed to find libc: %v", err)
	}

	fmt.Printf("%x - %x", addr.Start, addr.End)
}
