package active

import (
	"github.com/ZhuriLab/Starmap/pkg/resolve"
	"github.com/ZhuriLab/Starmap/pkg/util"
	"github.com/projectdiscovery/gologger"
)

func Enum(domain string, uniqueMap map[string]resolve.HostEntry, silent bool, fileName string, level int, levelDict string, dns string) map[string]resolve.HostEntry {
	gologger.Info().Msgf("Start DNS blasting of %s", domain)
	var levelDomains []string
	if levelDict != "" {
		dl, err := util.LinesInFile(levelDict)
		if err != nil {
			gologger.Fatal().Msgf("读取domain文件失败:%s,请检查--level-dict参数\n", err.Error())
		}
		levelDomains = dl
	} else {
		levelDomains = GetDefaultSubNextData()
	}

	var resolvers []string
	switch dns {
	case "cn":
		resolvers = resolve.DefaultResolversCN
	case "in":
		resolvers = resolve.DefaultResolvers
	case "all":
		resolvers = append(resolve.DefaultResolvers, resolve.DefaultResolversCN...)
	}

	opt := &Options {
		Rate:         Band2Rate("2m"),
		Domain:       domain,
		FileName:     fileName,
		Resolvers:    resolvers,
		Output:       "",
		Silent:       silent,
		SkipWildCard: false,
		TimeOut:      5,
		Retry:        6,
		Level:        level,  				// 枚举几级域名，默认为2，二级域名,
		LevelDomains: levelDomains,   		// 枚举多级域名的字典文件，当level大于2时候使用，不填则会默认
		Method:       "enum",
	}

	r, err := New(opt)
	if err != nil {
		gologger.Fatal().Msgf("%s", err)
	}

	enumMap := r.RunEnumeration(uniqueMap)

	r.Close()
	return enumMap
}

func Verify(uniqueMap map[string]resolve.HostEntry, silent bool, dns string) map[string]resolve.HostEntry {
	gologger.Info().Msgf("Start to verify the collected sub domain name results, a total of %d", len(uniqueMap))
	var resolvers []string
	switch dns {
	case "cn":
		resolvers = resolve.DefaultResolversCN
	case "in":
		resolvers = resolve.DefaultResolvers
	case "all":
		resolvers = append(resolve.DefaultResolvers, resolve.DefaultResolversCN...)
	}

	opt := &Options {
		Rate:         Band2Rate("2m"),
		Domain:       "",
		UniqueMap:    uniqueMap,
		Resolvers:    resolvers,
		Output:       "",
		Silent:       silent,
		SkipWildCard: false,
		TimeOut:      5,
		Retry:        6,
		Method:       "verify",
	}

	r, err := New(opt)
	if err != nil {
		gologger.Fatal().Msgf("%s", err)
	}

	AuniqueMap := r.RunEnumerationVerify(uniqueMap)

	r.Close()

	return AuniqueMap
}