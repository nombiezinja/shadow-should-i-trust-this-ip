package ipchecker

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// Should really be split into two tests, would improve readability
func TestChecker(t *testing.T) {
	cases := []struct {
		testCaseName                string
		Input                       interface{}
		Trusted                     bool
		AdditionalIPList            *IPList
		AdditionalCIDRRangeList     *CIDRRangeList
		Opts                        *Options
		ExpectedInitializationError error
		ExpectedResultError         error
	}{
		{
			"input is nil",
			nil,
			false,
			&IPList{IPs: []net.IP{}},
			&CIDRRangeList{Ranges: []net.IPNet{}},
			&Options{ExcludeSFDCCanonicalList: false},
			nil,
			errors.New(ErrMsgInvalidInput),
		},
		{
			"input is an integer",
			int32(4),
			false,
			&IPList{IPs: []net.IP{}},
			&CIDRRangeList{Ranges: []net.IPNet{}},
			&Options{ExcludeSFDCCanonicalList: false},
			nil,
			errors.New(ErrMsgInvalidInput),
		},
		{
			"input is a valid IP but not within the allowlist",
			"245.93.162.16",
			false,
			&IPList{IPs: []net.IP{}},
			&CIDRRangeList{Ranges: []net.IPNet{}},
			&Options{ExcludeSFDCCanonicalList: false},
			nil,
			errors.New(ErrMsgNotInAllowList),
		},
		{
			"input is a string but not an IP",
			"someString",
			false,
			&IPList{IPs: []net.IP{}},
			&CIDRRangeList{Ranges: []net.IPNet{}},
			&Options{ExcludeSFDCCanonicalList: false},
			nil,
			errors.New(ErrMsgInvalidInput),
		},
		{
			"input is not part of the canonical list, but is part of the additional list",
			"24.80.111.224",
			true,
			&IPList{IPs: []net.IP{net.IPv4(24, 80, 111, 224)}},
			&CIDRRangeList{Ranges: []net.IPNet{}},
			&Options{ExcludeSFDCCanonicalList: false},
			nil,
			nil,
		},
		{
			"initializing checker returns error due to bad config",
			"",
			false,
			&IPList{IPs: []net.IP{}},
			&CIDRRangeList{Ranges: []net.IPNet{}},
			&Options{ExcludeSFDCCanonicalList: true},
			errors.New(ErrMsgEmptyAllowlist),
			nil,
		},
		{
			"initializing checker returns error due to bad config but instead of empty slices, they are nils",
			"",
			false,
			nil,
			nil,
			&Options{ExcludeSFDCCanonicalList: true},
			errors.New(ErrMsgEmptyAllowlist),
			nil,
		},
		{
			"input is part of a canonical list ",
			"46.137.240.222",
			true,
			&IPList{IPs: []net.IP{}},
			&CIDRRangeList{Ranges: []net.IPNet{}},
			&Options{ExcludeSFDCCanonicalList: false},
			nil,
			nil,
		},
		{
			"input is part of a canonical list but option for ExcludeSFDCCanonicalList is configured as true",
			"13.110.54.11",
			false,
			&IPList{IPs: []net.IP{net.IPv4(24, 80, 111, 224)}},
			&CIDRRangeList{Ranges: []net.IPNet{}},
			&Options{ExcludeSFDCCanonicalList: true},
			nil,
			errors.New(ErrMsgNotInAllowList),
		},
		{
			"input is not part of the canonical list, nor a part of the additional list",
			"54.214.85.193",
			false,
			&IPList{IPs: []net.IP{net.IPv4(24, 80, 111, 224)}},
			&CIDRRangeList{Ranges: []net.IPNet{}},
			&Options{ExcludeSFDCCanonicalList: false},
			nil,
			errors.New(ErrMsgNotInAllowList),
		},
		{
			"input is not part of the canonical list, but is a part of the additional list (specifically, cidr ranges)",
			"192.168.1.244",
			true,
			&IPList{IPs: []net.IP{}},
			&CIDRRangeList{Ranges: []net.IPNet{
				{
					IP:   net.IPv4(192, 168, 1, 0),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
			}},
			&Options{ExcludeSFDCCanonicalList: true},
			nil,
			nil,
		},
	}

	for _, testCase := range cases {
		t.Run(fmt.Sprintf("%#v", testCase.Input), func(t *testing.T) {
			c, err := New(testCase.AdditionalIPList, testCase.AdditionalCIDRRangeList, testCase.Opts)
			require.Equal(t, testCase.ExpectedInitializationError, err)

			if c != nil {
				err = c.Check(testCase.Input)
				require.Equal(
					t, testCase.Trusted,
					err == testCase.ExpectedResultError,
				)
			}
		})
	}
}
