package ipchecker

import "net"

// canonicalTrustedIpList is pulled from https://confluence.internal.salesforce.com/pages/viewpage.action?spaceKey=BizTech&title=Salesforce+Public+IP%27s+-+Corp+IT
// Check to verify that it is still up to date before using this package.
var CanonicalTrustedIPList = IPList{
	IPs: []net.IP{
		net.ParseIP("50.112.137.68"),
		net.ParseIP("52.33.243.73"),
		net.ParseIP("54.218.242.77"),
		net.ParseIP("3.94.34.4"),
		net.ParseIP("3.95.94.115"),
		net.ParseIP("34.201.200.177"),
		net.ParseIP("3.0.250.21"),
		net.ParseIP("3.1.33.218"),
		net.ParseIP("46.137.240.222"),
		net.ParseIP("54.148.249.104"),
		net.ParseIP("54.214.85.193"),
		net.ParseIP("13.250.175.119"),
		net.ParseIP("52.220.254.0"),
	},
}

// canonicalTrustedCidrRanges is pulled from
// https://confluence.internal.salesforce.com/pages/viewpage.action?spaceKey=BizTech&title=Salesforce+Public+IP%27s+-+Corp+IT.
// Check to verify that it is still up to date before using this package.
var CanonicalTrustedCIDRRanges = CIDRRangeList{
	Ranges: []net.IPNet{
		{
			// "204.14.236.0/24"
			IP:   net.IPv4(204, 14, 236, 0),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		},
		{
			// "13.110.54.0/24"
			IP:   net.IPv4(13, 110, 54, 0),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		},
		{
			// "104.161.244.0/24"
			IP:   net.IPv4(104, 161, 244, 0),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		},
		{
			// "104.161.246.0/24",
			IP:   net.IPv4(104, 161, 246, 0),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		},
		{
			// "104.161.242.0/24"
			IP:   net.IPv4(104, 161, 242, 0),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		},
		{
			// "85.222.134.0/24"
			IP:   net.IPv4(85, 222, 134, 0),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		},
	},
}
