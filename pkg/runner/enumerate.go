package runner

import (
	"context"
	"github.com/ZhuriLab/Starmap/pkg/active"
	"github.com/ZhuriLab/Starmap/pkg/subTakeOver"
	"github.com/ZhuriLab/Starmap/pkg/util"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/ZhuriLab/Starmap/pkg/resolve"
	"github.com/ZhuriLab/Starmap/pkg/subscraping"
	"github.com/hako/durafmt"
	"github.com/projectdiscovery/gologger"
)

const maxNumCount = 2

// EnumerateSingleDomain performs subdomain enumeration against a single domain
func (r *Runner) EnumerateSingleDomain(ctx context.Context, domain string, outputs []io.Writer)  (error, map[string]resolve.HostEntry) {
	gologger.Info().Msgf("Enumerating subdomains for %s\n", domain)

	// Get the API keys for sources from the configuration
	// and also create the active resolving engine for the domain.
	keys := r.options.YAMLConfig.GetKeys()

	//// Check if the user has asked to remove wildcards explicitly.
	//// If yes, create the resolution pool and get the wildcards for the current domain
	//var resolutionPool *resolve.ResolutionPool
	//if r.options.RemoveWildcard {
	//	resolutionPool = r.resolverClient.NewResolutionPool(r.options.Threads, r.options.RemoveWildcard)
	//	err := resolutionPool.InitWildcards(domain)
	//	if err != nil {
	//		// Log the error but don't quit.
	//		gologger.Warning().Msgf("Could not get wildcards for domain %s: %s\n", domain, err)
	//	}
	//}

	// Run the passive subdomain enumeration
	now := time.Now()
	passiveResults := r.passiveAgent.EnumerateSubdomains(domain, &keys, r.options.Proxy, r.options.RateLimit, r.options.Timeout, time.Duration(r.options.MaxEnumerationTime)*time.Minute)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	// Create a unique map for filtering duplicate subdomains out
	uniqueMap := make(map[string]resolve.HostEntry)
	// Create a map to track sources for each host
	sourceMap := make(map[string]map[string]struct{})
	// Process the results in a separate goroutine
	go func() {
		for result := range passiveResults {
			switch result.Type {
			case subscraping.Error:
				gologger.Warning().Msgf("Could not run source %s: %s\n", result.Source, result.Error)
			case subscraping.Subdomain:
				// Validate the subdomain found and remove wildcards from
				if result.Value != domain && !strings.HasSuffix(result.Value, "."+domain) {
					continue
				}
				subdomain := strings.ReplaceAll(strings.ToLower(result.Value), "*.", "")

				if _, ok := uniqueMap[subdomain]; !ok {
					sourceMap[subdomain] = make(map[string]struct{})
				}

				// Log the verbose message about the found subdomain per source
				if _, ok := sourceMap[subdomain][result.Source]; !ok {
					gologger.Verbose().Label(result.Source).Msg(subdomain)
				}

				sourceMap[subdomain][result.Source] = struct{}{}

				// Check if the subdomain is a duplicate. If not,
				// send the subdomain for resolution.
				if _, ok := uniqueMap[subdomain]; ok {
					if result.IpPorts != nil {
						tmp := uniqueMap[subdomain].IpPorts
						if tmp != nil {
							tmp = util.MergeIpPortMap(tmp, result.IpPorts)
							hostEntry := resolve.HostEntry{Host: subdomain, Source: result.Source, IpPorts: tmp}
							uniqueMap[subdomain] = hostEntry
						} else {
							hostEntry := resolve.HostEntry{Host: subdomain, Source: result.Source, IpPorts: result.IpPorts}
							uniqueMap[subdomain] = hostEntry
						}

					}
					continue

				}

				hostEntry := resolve.HostEntry{Host: subdomain, Source: result.Source, IpPorts: result.IpPorts}

				uniqueMap[subdomain] = hostEntry

				// If the user asked to remove wildcard then send on the resolve
				// queue. Otherwise, if mode is not verbose print the results on
				// the screen as they are discovered.
				//
			}
		}
		//// Close the task channel only if wildcards are asked to be removed
		//if r.options.RemoveWildcard {
		//	close(resolutionPool.Tasks)
		//}
		wg.Done()
	}()

	// If the user asked to remove wildcards, listen from the results
	// queue and write to the map. At the end, print the found results to the screen
	//foundResults := make(map[string]resolve.Result)
	//if r.options.RemoveWildcard {
	//	// Process the results coming from the resolutions pool
	//	for result := range resolutionPool.Results {
	//		switch result.Type {
	//		case resolve.Error:
	//			gologger.Warning().Msgf("Could not resolve host: %s\n", result.Error)
	//		case resolve.Subdomain:
	//			// Add the found subdomain to a map.
	//			if _, ok := foundResults[result.Host]; !ok {
	//				foundResults[result.Host] = result
	//			}
	//		}
	//	}
	//}
	wg.Wait()


	var wildcardIPs map[string]struct{}

	var wildcardIPsAc map[string]struct{}

	if r.options.RemoveWildcard {
		gologger.Info().Msgf("%s 检测泛解析", domain)
		var err error
		// 泛解析客户端初始化
		r.resolverClient = resolve.New()

		r.resolverClient.DNSClient, err = dnsx.New(dnsx.Options{BaseResolvers: r.Resolvers, MaxRetries: 5})

		if err != nil {
			gologger.Error().Msgf("泛解析客户端初始化错误: %s", err)
		}

		err, wildcardIPs = resolve.InitWildcards(r.resolverClient, domain, r.Resolvers, r.options.MaxWildcardChecks)
		if err != nil {
			// Log the error but don't quit.
			gologger.Warning().Msgf("Could not get wildcards for domain %s: %s\n", domain, err)
		}

		if len(wildcardIPs) > 0 {
			gologger.Info().Msgf("域名:%s 存在泛解析, 自动过滤泛解析， %v\n", domain, wildcardIPs)
		}
	}

	if r.options.Verify { // 验证模式
		l := len(uniqueMap)
		uniqueMap, wildcardIPsAc = active.Verify(uniqueMap, r.options.Silent, r.Resolvers, wildcardIPs, r.options.MaxIps)
		gologger.Info().Msgf("A total of %d were collected in passive mode, and %d were verified to be alive", l, len(uniqueMap))

	} else {
		gologger.Info().Msgf("Passive acquisition end, Found %d subdomains.", len(uniqueMap))
	}

	time.Sleep(5*time.Second)
	if r.options.Brute {
		if r.options.Number > 1 {
			n := make(map[string]resolve.HostEntry)
			// dns 爆破次数
			for i := 1; i <= r.options.Number; i++ {
				var test map[string]resolve.HostEntry
				test, wildcardIPsAc = active.Enum(domain, uniqueMap, r.options.Silent, r.options.BruteWordlist, r.options.Level, r.options.LevelDic, r.Resolvers, wildcardIPs, r.options.MaxIps)
				if i > 1 {
					n = util.MergeMap(uniqueMap, test)
				}
				uniqueMap = test
			}
			uniqueMap = n
		} else {
			uniqueMap, wildcardIPsAc = active.Enum(domain, uniqueMap, r.options.Silent, r.options.BruteWordlist, r.options.Level, r.options.LevelDic, r.Resolvers, wildcardIPs, r.options.MaxIps)
		}

	}

	// 子域名接管检测
	if r.options.Takeover {
		gologger.Info().Msgf("Start subdomain takeover ...")
		uniqueMap = subTakeOver.Process(uniqueMap, r.options.SAll, r.options.Verbose)
	}



	// 泛解析再次处理
	if len(wildcardIPsAc) > 0 {
		for _, result := range uniqueMap {
			if result.IpPorts != nil {
				var ips []string
				for k, _ := range result.IpPorts {
					ips = append(ips, k)
				}

				if _, ok := wildcardIPsAc[ips[0]]; ok {
					delete(uniqueMap, result.Host)
				}
			}
		}
	}


	outputter := NewOutputter(r.options.JSON)

	// Now output all results in output writers
	var err error
	for _, w := range outputs {
		if r.options.CaptureSources {
			err = outputter.WriteSourceHost(sourceMap, w)
		} else {
			err = outputter.WriteHost(uniqueMap, w)
		}

		//if r.options.HostIP {
		//	err = outputter.WriteHostIP(foundResults, w)
		//} else {
			//if r.options.RemoveWildcard {
			//	err = outputter.WriteHostNoWildcard(foundResults, w)
			//} else {
			//	if r.options.CaptureSources {
			//		err = outputter.WriteSourceHost(sourceMap, w)
			//	} else {
			//		err = outputter.WriteHost(uniqueMap, w)
			//	}
			//}
		//}
		if err != nil {
			gologger.Error().Msgf("Could not verbose results for %s: %s\n", domain, err)
			return err, nil
		}
	}

	// Show found subdomain count in any case.
	duration := durafmt.Parse(time.Since(now)).LimitFirstN(maxNumCount).String()

	gologger.Info().Msgf("Found %d subdomains for %s in %s\n", len(uniqueMap), domain, duration)
	return nil, uniqueMap
}
