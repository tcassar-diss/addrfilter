package frontend

import (
	"encoding/json"
	"io"
	"os"
	"strconv"

	"github.com/BurntSushi/toml"
)

type Whitelist struct {
	NameSyscallMap map[string][]uint
}

type whitelistTOML struct {
	NameSyscallMap map[string][]uint `toml:"files"`
}

func ParseTOMLWhitelists(filepath string) (*Whitelist, error) {
	var parsed whitelistTOML

	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if _, err := toml.NewDecoder(file).Decode(&parsed); err != nil {
		return nil, err
	}

	if calls, ok := parsed.NameSyscallMap["FAILED"]; ok {
		delete(parsed.NameSyscallMap, "FAILED")

		for k := range parsed.NameSyscallMap {
			parsed.NameSyscallMap[k] = append(parsed.NameSyscallMap[k], calls...)
		}
	}

	return &Whitelist{NameSyscallMap: parsed.NameSyscallMap}, nil
}

func MarshalTOMLWhitelists(file io.Writer, wl *Whitelist) error {
	tomlData := whitelistTOML{
		NameSyscallMap: wl.NameSyscallMap,
	}

	encoder := toml.NewEncoder(file)
	if err := encoder.Encode(tomlData); err != nil {
		return err
	}

	return nil
}

func ParseSysoWhitelists(filepath string) (*Whitelist, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var raw map[string]map[string]int
	if err := json.NewDecoder(file).Decode(&raw); err != nil {
		return nil, err
	}

	result := make(map[string][]uint)

	// Extract keys (syscall numbers), ignore values
	for path, syscallMap := range raw {
		if len(syscallMap) == 0 {
			result[path] = []uint{}
		}

		for k := range syscallMap {
			if n, err := strconv.ParseUint(k, 10, 64); err == nil {
				result[path] = append(result[path], uint(n))
			}
		}
	}

	if calls, ok := result["FAILED"]; ok {
		delete(result, "FAILED")
		for k := range result {
			result[k] = append(result[k], calls...)
		}
	}

	return &Whitelist{NameSyscallMap: result}, nil
}
