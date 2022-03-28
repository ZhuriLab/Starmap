package net

// DNSAnswer is the type used by Amass to represent a DNS record.
type DNSAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

// DNSRequest handles data needed throughout Service processing of a DNS name.
type DNSRequest struct {
	Name    string
	Domain  string
	Records []DNSAnswer
	Tag     string
	Source  string
}

// Request tag types.
const (
	NONE     = "none"
	ALT      = "alt"
	GUESS    = "guess"
	ARCHIVE  = "archive"
	API      = "api"
	AXFR     = "axfr"
	BRUTE    = "brute"
	CERT     = "cert"
	CRAWL    = "crawl"
	DNS      = "dns"
	RIR      = "rir"
	EXTERNAL = "ext"
	SCRAPE   = "scrape"
)
