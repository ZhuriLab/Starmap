package active

import (
	"github.com/ZhuriLab/Starmap/pkg/resolve"
	"github.com/projectdiscovery/gologger"
	"strconv"
)

type Options struct {
	Rate         int64
	Domain       string
	FileName     string // 字典文件名
	Resolvers    []string
	Output       string // 输出文件名
	Silent       bool
	WildcardIPs  map[string]struct{}
	TimeOut      int
	Retry        int
	Method       string // verify模式 enum模式 test模式
	Level        int
	LevelDomains []string
	UniqueMap    map[string]resolve.HostEntry
}

func Band2Rate(bandWith string) int64 {
	suffix := string(bandWith[len(bandWith)-1])
	rate, _ := strconv.ParseInt(string(bandWith[0:len(bandWith)-1]), 10, 64)
	switch suffix {
	case "G":
		fallthrough
	case "g":
		rate *= 1000000000
	case "M":
		fallthrough
	case "m":
		rate *= 1000000
	case "K":
		fallthrough
	case "k":
		rate *= 1000
	default:
		gologger.Fatal().Msgf("unknown bandwith suffix '%s' (supported suffixes are G,M and K)\n", suffix)
	}
	packSize := int64(80) // 一个DNS包大概有74byte
	rate = rate / packSize
	return rate
}

