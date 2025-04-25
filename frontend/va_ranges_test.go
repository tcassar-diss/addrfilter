package frontend

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindLibc(t *testing.T) {
	type testcase struct {
		filepath string
		vmRange  *VMRange
		err      error
	}

	cwd, err := os.Getwd()
	require.NoError(t, err)

	testVARoot := path.Join(cwd, "../test-resources/test_vas")

	cases := []testcase{
		{
			filepath: path.Join(testVARoot, "1", "maps"),
			vmRange: &VMRange{
				Start: 0x726951400000,
				End:   0x726951605000,
			},
			err: nil,
		},
		{
			filepath: path.Join(testVARoot, "2", "maps"),
			vmRange:  nil,
			err:      ErrFindLibcFailed,
		},
		{
			filepath: path.Join(testVARoot, "3", "maps"),
			vmRange:  nil,
			err:      ErrFindLibcFailed,
		},
	}

	for _, c := range cases {
		t.Run(c.filepath, func(t *testing.T) {
			gotVMRange, gotErr := FindLibc(c.filepath, nil)

			require.Equal(t, c.vmRange, gotVMRange)
			if c.err != nil {
				require.ErrorIs(t, gotErr, c.err)
			}
		})
	}
}
