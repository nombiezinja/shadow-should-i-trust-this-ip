package ipchecker

import "net"

type Checker struct {
	TrustedCIDRRanges CIDRRangeList
	TrustedIPs        IPList
}

type Options struct {
	// If set to true, then checker will check the cannonical allowlist in canonical_allow_list.go
	ExcludeSFDCCanonicalList bool
}

type CIDRRangeList struct {
	Ranges []net.IPNet
}

type IPList struct {
	IPs []net.IP
}

const (
	ErrMsgEmptyAllowlist string = "If no additional ip list and cidr ranges are passed AND ExcludeSFDCCanonicalList is set to true, there would be no list to validate against"
	ErrMsgInvalidInput   string = "Must be a interface that can be cast to a string"
	ErrMsgInvalidIP      string = "Must be a valid IP"
	ErrMsgNotInAllowList string = "This IP is not part of the allowlist."
)
