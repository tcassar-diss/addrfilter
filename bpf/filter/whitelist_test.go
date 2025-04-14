package filter

import (
	"errors"
	"testing"
)

func TestWhitelist_AsBitmap(t *testing.T) {
	tests := []struct {
		name      string
		whitelist Whitelist
		expected  [58]uint8
		err       error
	}{
		{
			name:      "Single syscall",
			whitelist: Whitelist{Filename: "test1", Syscalls: []uint{3}},
			expected: func() [58]uint8 {
				var b [58]uint8
				b[0] = 1 << 3
				return b
			}(),
			err: nil,
		},
		{
			name:      "Multiple syscalls",
			whitelist: Whitelist{Filename: "test2", Syscalls: []uint{3, 10, 23}},
			expected: func() [58]uint8 {
				var b [58]uint8
				b[0] = 1 << 3
				b[1] = 1 << 2
				b[2] = 1 << 7
				return b
			}(),
			err: nil,
		},
		{
			name:      "Out of range syscall",
			whitelist: Whitelist{Filename: "test3", Syscalls: []uint{500}},
			expected:  [58]uint8{},
			err:       ErrInvalidSyscallNr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.whitelist.AsBitmap()

			if !errors.Is(err, tt.err) {
				t.Errorf("AsBitmap() err = %v, expected %v", err, tt.err)
			}

			if got != tt.expected {
				t.Errorf("AsBitmap() value = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestWhitelist_MarshalFilename(t *testing.T) {
	tests := []struct {
		name      string
		whitelist Whitelist
		expected  [256]byte
		err       error
	}{
		{
			name:      "hello",
			whitelist: Whitelist{Filename: "hello"},
			expected:  [256]byte{104, 101, 108, 108, 111, 00},
			err:       nil,
		},
		{
			name:      "too long",
			whitelist: Whitelist{Filename: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Syscalls: []uint{3, 10, 23}},
			expected:  [256]byte{},
			err:       ErrFilenameMarshalFailed,
		},
		{
			name:      "file name non-existent",
			whitelist: Whitelist{Filename: "", Syscalls: []uint{500}},
			expected:  [256]byte{0x00},
			err:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.whitelist.MarshalFilename()

			if !errors.Is(err, tt.err) {
				t.Errorf("MarshallFilename() err = %v, expected %v", err, tt.err)
			}

			if got != tt.expected {
				t.Errorf("MarshallFilename() value = %v, expected %v", got, tt.expected)
			}
		})
	}
}
