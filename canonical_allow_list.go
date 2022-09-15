package ipchecker

import "net"

// List pulled from https://confluence.internal.salesforce.com/pages/viewpage.action?spaceKey=BizTech&title=Salesforce+Public+IP%27s+-+Corp+IT
var TRUSTED_IPS = []string{
	"50.112.137.68",
	"52.33.243.73",
	"54.218.242.77",
	"3.94.34.4",
	"3.95.94.115",
	"34.201.200.177",
	"3.0.250.21",
	"3.1.33.218",
	"46.137.240.222",
	"54.148.249.104",
	"54.214.85.193",
	"13.250.175.119",
	"52.220.254.0",
}

var TRUSTED_CIDR_RANGES = []net.IPNet{
	{
		// 	204.14.236.0/24
		IP:   net.IPv4(204, 14, 236, 0),
		Mask: net.IPv4Mask(255, 255, 255, 0),
	},
	{
		//	"13.110.54.0/24",
		IP:   net.IPv4(13, 110, 54, 0),
		Mask: net.IPv4Mask(255, 255, 255, 0),
	},
	{
		// "104.161.244.0/24",
		IP:   net.IPv4(104, 161, 244, 0),
		Mask: net.IPv4Mask(255, 255, 255, 0),
	},
	{
		// "104.161.246.0/24",
		IP:   net.IPv4(104, 161, 246, 0),
		Mask: net.IPv4Mask(255, 255, 255, 0),
	},
	{
		// "104.161.242.0/24",
		IP:   net.IPv4(104, 161, 242, 0),
		Mask: net.IPv4Mask(255, 255, 255, 0),
	},
	{
		// "85.222.134.0/24",
		IP:   net.IPv4(85, 222, 134, 0),
		Mask: net.IPv4Mask(255, 255, 255, 0),
	},
}
