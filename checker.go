package ipchecker

import (
	"errors"
	"net"
)

// New initializes a new Checker.
// Passing an additional IP list and/or an additional list of CIDR ranges
// will result in the checker counting those as part of the allowlist.
// It is also possible to configure the checker to exclude the canonical list
// of IPs in https://confluence.internal.salesforce.com/pages/viewpage.action?spaceKey=BizTech&title=Salesforce+Public+IP%27s+-+Corp+IT
// However, it is not possible to do both as that will result in an empty allowlist.
func New(ipList *IPList, cidrRanges *CIDRRangeList, opts *Options) (*Checker, error) {
	// This check is a bit silly to enable the ability to either pass empty slices or nils
	// for the additional lists.
	additionalListIsEmpty := (ipList == nil && cidrRanges == nil) || (len(ipList.IPs) == 0 && len(cidrRanges.Ranges) == 0)
	if opts.ExcludeSFDCCanonicalList == true && additionalListIsEmpty {
		return nil, errors.New(ErrMsgEmptyAllowlist)
	}

	c := &Checker{
		TrustedCIDRRanges: CIDRRangeList{Ranges: []net.IPNet{}},
		TrustedIPs:        IPList{IPs: []net.IP{}},
	}

	// Append canonical allowlist if so desired
	c.TrustedCIDRRanges.Ranges = append(c.TrustedCIDRRanges.Ranges, CanonicalTrustedCIDRRanges.Ranges...)
	c.TrustedIPs.IPs = append(c.TrustedIPs.IPs, CanonicalTrustedIPList.IPs...)

	// Append additional IPs and CIDRs to be added as "trusted" by checker
	c.TrustedCIDRRanges.Ranges = append(c.TrustedCIDRRanges.Ranges, cidrRanges.Ranges...)
	c.TrustedIPs.IPs = append(c.TrustedIPs.IPs, ipList.IPs...)

	return c, nil
}

// Check takes a value and checks whether it's within the allowlist
// Nil error means the IP has passed the check and is within the configured
// allowlist
func (c *Checker) Check(value interface{}) error {
	s, ok := value.(string)
	if !ok {
		return errors.New(ErrMsgInvalidInput)
	}

	ip := net.ParseIP(s)
	if ip == nil {
		return errors.New(ErrMsgInvalidIP)
	}

	// Check the list of trusted IPs
	for _, trustedIP := range c.TrustedIPs.IPs {
		if trustedIP.Equal(ip) {
			// Flip the flag and return early if IP is found within the list of trusted IPs
			return nil
		}
	}

	// check the trusted CIDR ranges
	for _, trustedRange := range c.TrustedCIDRRanges.Ranges {
		if trustedRange.Contains(ip) {
			// Return early if IP is found within any 1 of the ranges.
			return nil
		}
	}

	// Return an error if the IP address is not contained within
	// any of the expected ranges.
	return errors.New(ErrMsgNotInAllowList)
}
