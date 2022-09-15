package ipchecker

import (
	"fmt"
	"net"
)

func Check(value interface{}) error {
	// assert that value is of type string.
	s, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a valid string")
	}

	trusted := false

	// check the list of trusted IPs
	for _, trustedIp := range TRUSTED_IPS {
		if trustedIp == s {
			// Return early if IP is found within the list of trusted IPs
			trusted = true
			return nil
		}
	}

	ip := net.ParseIP(s)

	// check the trusted CIDR ranges
	for _, trustedRange := range TRUSTED_CIDR_RANGES {
		if trustedRange.Contains(ip) {
			// Flip flag if IP is found within any 1 of the ranges.
			trusted = true
			return nil
		}
	}

	// Check flag and return an error if the IP address is not contained within
	// any of the expected ranges.
	if !trusted {
		return fmt.Errorf("This IP is not part of the allowlist.")
	}

	return nil
}
