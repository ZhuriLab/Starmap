package resolve

import (
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// DefaultResolvers contains the default list of resolvers known to be good
var DefaultResolvers = []string {
	"1.1.1.1",			// Cloudflare
	"1.0.0.1",        	// Cloudlfare secondary
	"8.8.8.8",        	// Google
	"8.8.4.4",        	// Google secondary
	"9.9.9.9",        	// Quad9
	"9.9.9.10",       	// Quad9 Secondary
	"77.88.8.8",     // Yandex Primary
	"77.88.8.1",     // Yandex Secondary
	"208.67.222.222", 	// Cisco OpenDNS
	"208.67.220.220",   // OpenDNS Secondary
}

// DefaultResolversCN contains the default list of resolvers known to be good
var DefaultResolversCN = []string{
	"223.5.5.5",	  	// AliDNS
	"223.6.6.6", 		// AliDNS
	"119.29.29.29",   	// DNSPod
	"114.114.114.114",	// 114DNS
	"114.114.115.115", 	// 114DNS
	"101.226.4.6",		// DNS 派
	"117.50.11.11", 	// One(微步) DNS
	"52.80.66.66",		// One(微步) DNS
	"1.2.4.8",			// CNNIC
	"210.2.4.8",		// CNNIC
}

// Resolver is a struct for resolving DNS names
type Resolver struct {
	DNSClient *dnsx.DNSX
	Resolvers []string
}

// New creates a new resolver struct with the default resolvers
func New() *Resolver {
	return &Resolver{
		Resolvers: []string{},
	}
}
