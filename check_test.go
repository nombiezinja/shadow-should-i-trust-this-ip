package ipchecker

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheck(t *testing.T) {
	cases := []struct {
		Input interface{}
		Valid bool
	}{
		{
			nil,
			false,
		},
		{
			int32(4),
			false,
		},
		{
			"245.93.162.16",
			false,
		},
		{
			"someString",
			false,
		},
	}

	cases = append(cases, struct {
		Input interface{}
		Valid bool
	}{
		nil, false,
	})

	for _, tt := range cases {
		t.Run(fmt.Sprintf("%#v", tt.Input), func(t *testing.T) {
			err := Check(tt.Input)
			require.Equal(t, tt.Valid, err == nil)
		})
	}
}
