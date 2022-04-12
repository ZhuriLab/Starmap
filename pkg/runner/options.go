package runner

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path"
	"reflect"
	"strings"

	"github.com/ZhuriLab/Starmap/pkg/goflags"
	"github.com/projectdiscovery/gologger"
)


type Options struct {
	Verbose        bool // Verbose flag indicates whether to show verbose output or not
	NoColor        bool // No-Color disables the colored output
	JSON           bool // JSON specifies whether to use json for output format or text file
	HostIP         bool // HostIP specifies whether to write subdomains in host:ip format
	Silent         bool // Silent suppresses any extra text and only writes subdomains to screen
	ListSources    bool // ListSources specifies whether to list all available sources
	RemoveWildcard bool // RemoveWildcard specifies whether to remove potential wildcard or dead subdomains from the results.
	CaptureSources bool // CaptureSources specifies whether to save all sources that returned a specific domains or just the first source
	Stdin          bool // Stdin specifies whether stdin input was given to the process
	Version        bool // Version specifies if we should just show version and exit
	OnlyRecursive  bool // Recursive specifies whether to use only recursive subdomain enumeration sources
	// Recrusive contains the list of recursive subdomain enum sources
	Recursive goflags.NormalizedStringSlice `yaml:"recursive,omitempty"`
	All       bool                          // All specifies whether to use all (slow) sources.
	// AllSources contains the list of all sources for enumeration (slow)
	AllSources         goflags.NormalizedStringSlice `yaml:"all-sources,omitempty"`
	Threads            int                           // Thread controls the number of threads to use for active enumerations
	Timeout            int                           // Timeout is the seconds to wait for sources to respond
	MaxEnumerationTime int                           // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
	Domain             goflags.NormalizedStringSlice // Domain is the domain to find subdomains for
	DomainsFile        string                        // DomainsFile is the file containing list of domains to find subdomains for
	Output             io.Writer
	OutputFile         string // Output is the file to write found subdomains to.
	OutputDirectory    string // OutputDirectory is the directory to write results to in case list of domains is given
	// Sources contains a comma-separated list of sources to use for enumeration
	Sources goflags.NormalizedStringSlice `yaml:"sources,omitempty"`
	// ExcludeSources contains the comma-separated sources to not include in the enumeration process
	ExcludeSources goflags.NormalizedStringSlice `yaml:"exclude-sources,omitempty"`
	// Resolvers is the comma-separated resolvers to use for enumeration
	Resolvers      goflags.NormalizedStringSlice `yaml:"resolvers,omitempty"`
	ResolverList   string                        // ResolverList is a text file containing list of resolvers to use for enumeration
	Config         string                        // Config contains the location of the config file
	Proxy          string                        // HTTP proxy
	RateLimit      int                           // Maximum number of HTTP requests to send per second
	YAMLConfig 		Providers // YAMLConfig contains the unmarshalled yaml config file

	BruteWordlist      string // BruteWordlist is path to a different wordlist file for brute forcing
	LevelDic      	   string // LevelDic is path to a different wordlist file for brute forcing
	Level      	   	   int 	// Level Number of blasting subdomain layers
	Brute			   bool   // Brute Use DNS brute forcing subdomain
	Number 			   int   // Number of DNS forced subdomains
	Verify 			   bool   // Verify is DNS authentication
	DNS                string // DNS server
	Takeover		   bool   // subdomain takeover
	SAll               bool   // Request to test each URL (by default, only the URL matching CNAME is requested to test).
	MaxWildcardChecks  int		// MaxWildcardChecks Number of random domain names
	MaxIps             int
}


// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	config, err := GetConfigDirectory()

	if err != nil {
		// This should never be reached
		gologger.Fatal().Msgf("Could not get user home: %s\n", err)
	}

	options := &Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Starmap is a subdomain discovery tool that discovers subdomains for websites by using passive online sources and DNS brute.`)

	createGroup(flagSet, "input", "Input",
		flagSet.NormalizedStringSliceVarP(&options.Domain, "domain", "d", []string{}, "domains to find subdomains for\n枚举的目标域名"),
		flagSet.StringVarP(&options.DomainsFile, "list", "dL", "", "file containing list of domains for subdomain discovery\n枚举的域名列表的文件"),
	)

	createGroup(flagSet, "source", "Source",
		flagSet.NormalizedStringSliceVarP(&options.Sources, "sources", "s", []string{}, "specific sources to use for discovery (-s crtsh,github)\n被动使用的源"),
		flagSet.BoolVar(&options.OnlyRecursive, "recursive", false, "use only recursive sources\n仅使用递归源"),
		flagSet.BoolVar(&options.All, "all", false, "Use all sources (slow) for enumeration\n使用所有源进行枚举"),
		flagSet.NormalizedStringSliceVarP(&options.ExcludeSources, "exclude-sources", "es", []string{}, "sources to exclude from enumeration (-es archiveis,zoomeye)\n 被动枚举中排除使用的源列表"),
	)

	//createGroup(flagSet, "rate-limit", "Rate-limit",
	//	flagSet.IntVarP(&options.RateLimit, "rate-limit", "rl", 0, "maximum number of http requests to send per second"),
	//	flagSet.IntVar(&options.Threads, "t", 10, "number of concurrent goroutines for resolving (-active only)"),
	//)
	options.RateLimit = 0
	options.Threads = 10

	createGroup(flagSet, "output", "Output",
		flagSet.StringVarP(&options.OutputFile, "output", "o", "", "file to write output to\n输出文件名"),
		flagSet.BoolVarP(&options.JSON, "json", "oJ", false, "write output in JSONL(ines) format\nJson格式输出，该选项输出内容丰富,输出到文件需要配合 -o res.json"),
		//flagSet.StringVarP(&options.OutputDirectory, "output-dir", "oD", "", "directory to write output (-dL only)"),
		//flagSet.BoolVarP(&options.CaptureSources, "collect-sources", "cs", false, "include all sources in the output (-json only)"),
		//flagSet.BoolVarP(&options.HostIP, "ip", "oI", false, "include host IP in output (-active only)"),
	)
	options.OutputDirectory = ""
	options.CaptureSources = false
	options.HostIP = false

	createGroup(flagSet, "configuration", "Configuration",
		flagSet.StringVar(&options.Config, "config", path.Join(config, "config.yaml"), "flag config file\n自定义API密钥等的配置文件位置"),
		//flagSet.NormalizedStringSliceVar(&options.Resolvers, "r", []string{}, "comma separated list of resolvers to use"),
		//flagSet.StringVarP(&options.ResolverList, "rlist", "rL", "", "file containing list of resolvers to use"),
		flagSet.StringVar(&options.Proxy, "proxy", "", "http proxy to use with subfinder\n指定被动api获取子域名时的代理"),
	)
	options.Resolvers = nil
	options.ResolverList = ""

	createGroup(flagSet, "debug", "Debug",
		flagSet.BoolVar(&options.Silent, "silent", false, "show only subdomains in output\n使用后屏幕将仅输出结果域名"),
		flagSet.BoolVar(&options.Version, "version", false, "show version of Starmap\n输出当前版本"),
		flagSet.BoolVar(&options.Verbose, "v", false, "show verbose output\n显示详细输出"),
		//flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "disable color in output"),
		//flagSet.BoolVarP(&options.ListSources, "list-sources", "ls", false, "list all available sources"),
	)
	options.NoColor = false
	options.ListSources = false

	//createGroup(flagSet, "optimization", "Optimization",
	//	flagSet.IntVar(&options.Timeout, "timeout", 30, "seconds to wait before timing out"),
	//	flagSet.IntVar(&options.MaxEnumerationTime, "max-time", 10, "minutes to wait for enumeration results"),
	//)
	options.Timeout = 30
	options.MaxEnumerationTime = 10

	createGroup(flagSet, "brute", "DNS Brute Forcing Subdomain",
		flagSet.StringVar(&options.BruteWordlist, "w", "", "Path to a different wordlist file for brute forcing\ndns 爆破使用的字典"),
		flagSet.StringVar(&options.LevelDic, "ld", "", "Multilevel subdomain dictionary(level > 2 use)\ndns 枚举多级域名的字典文件，当level大于2时候使用，不填则会默认"),
		flagSet.IntVar(&options.Level, "l", 2, "Number of blasting subdomain layers\n枚举几级域名，默认为二级域名"),
		flagSet.IntVar(&options.Number, "n", 1, "Number of DNS forced subdomains\ndns爆破每个域名的次数，默认跑一次"),
		flagSet.BoolVarP(&options.Brute, "brute",  "b",false, "Use DNS brute forcing subdomain(default false)\n被动加 dns 主动爆破(默认不使用)"),
		flagSet.BoolVar(&options.Verify, "verify", false, "DNS authentication survival, Export only verified domain names\n验证被动获取的域名，使用后仅输出验证存活的域名"),
		flagSet.StringVar(&options.DNS, "dns", "cn", "DNS server, cn:China dns, in:International, all:(cn+in DNS), conf:(read ./config/Starmap/config.yaml), Select according to the target. \nDNS服务器，默认国内的服务器(cn)(cn: 表示使用国内的 dns, in:国外 dns，all: 全部内置 dns, conf: 从配置文件 ./config/Starmap/config.yaml获取)，根据目标选择"),
		flagSet.BoolVarP(&options.RemoveWildcard, "active", "rW", false, "Domain name pan resolution filtering\n爆破时过滤泛解析(default false)"),
		flagSet.IntVar(&options.MaxWildcardChecks, "mW", 0, "Number of random domain names during universal resolution detection(default len(resolvers)*2)\n泛解析检测时的随机域名数量(default len(resolvers)*2)"),
		flagSet.IntVar(&options.MaxIps, "mI", 100, "When blasting, if more than a certain number of domain names point to the same IP, it is considered as universal resolution(default 100)\n爆破时如果超出一定数量的域名指向同一个 ip，则认为是泛解析(default 100)"),

	)

	createGroup(flagSet, "takeover", "subdomain takeover",
		flagSet.BoolVar(&options.Takeover, "takeover", false, " Scan subdomain takeover (default False).\n子域名接管检测 (默认：false)"),
		flagSet.BoolVar(&options.SAll, "sa", false, "subdomain take over: Request to test each URL (by default, only the URL matching CNAME is requested to test).\n子域名接管检测：请求测试每个URL（默认情况下，仅请求测试与CNAME匹配的URL）"),
	)

	if err := flagSet.Parse(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// Default output is stdout
	options.Output = os.Stdout

	// Check if stdin pipe was given
	options.Stdin = hasStdin()

	// Read the inputs and configure the logging
	options.ConfigureOutput()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", Version)
		os.Exit(0)
	}

	// Check if the application loading with any provider configuration, then take it
	// Otherwise load the default provider config
	if !CheckConfigExists(options.Config) {
		options.firstRunTasks()
	} else {
		options.normalRunTasks()
	}
	if options.ListSources {
		listSources(options)
		os.Exit(0)
	}

	options.preProcessOptions()

	if !options.Silent {
		showBanner()
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err = options.validateOptions()
	if err != nil {
		gologger.Fatal().Msgf("Program exiting: %s\n", err)
	}

	return options
}

func isFatalErr(err error) bool {
	return err != nil && !errors.Is(err, io.EOF)
}

func hasStdin() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	isPipedFromChrDev := (stat.Mode() & os.ModeCharDevice) == 0
	isPipedFromFIFO := (stat.Mode() & os.ModeNamedPipe) != 0

	return isPipedFromChrDev || isPipedFromFIFO
}

func listSources(options *Options) {
	gologger.Info().Msgf("Current list of available sources. [%d]\n", len(options.AllSources))
	gologger.Info().Msgf("Sources marked with an * needs key or token in order to work.\n")
	gologger.Info().Msgf("You can modify %s to configure your keys / tokens.\n\n", options.Config)

	keys := options.YAMLConfig.GetKeys()
	needsKey := make(map[string]interface{})
	keysElem := reflect.ValueOf(&keys).Elem()
	for i := 0; i < keysElem.NumField(); i++ {
		needsKey[strings.ToLower(keysElem.Type().Field(i).Name)] = keysElem.Field(i).Interface()
	}

	for _, source := range options.AllSources {
		message := "%s\n"
		if _, ok := needsKey[source]; ok {
			message = "%s *\n"
		}
		gologger.Silent().Msgf(message, source)
	}
}

func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}

func (options *Options) preProcessOptions() {
	for i, domain := range options.Domain {
		options.Domain[i], _ = sanitize(domain)
	}
}

func userHomeDir() string {
	usr, err := user.Current()
	if err != nil {
		gologger.Fatal().Msgf("Could not get user home directory: %s\n", err)
	}
	return usr.HomeDir
}
