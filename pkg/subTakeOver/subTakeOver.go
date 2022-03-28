package subTakeOver

import (
	"encoding/json"
	"fmt"
	"github.com/ZhuriLab/Starmap/pkg/resolve"
	"github.com/ZhuriLab/Starmap/pkg/subTakeOver/assets"
	"github.com/projectdiscovery/gologger"
	"sync"
)

type Options struct {
	Timeout      	int
	Ssl         	bool
	All          	bool
	Verbose			bool
	Fingerprints 	[]Fingerprints
}

// Process Start processing subTakeOver from the defined options.
func Process(uniqueMap map[string]resolve.HostEntry, all, verbose bool) map[string]resolve.HostEntry{
	hostEntrys := make(chan resolve.HostEntry, 99)

	var data []Fingerprints
	err := json.Unmarshal(assets.Fingerprints, &data)
	if err != nil {
		gologger.Fatal().Msgf("%s", err)
	}

	o := &Options {
		Timeout : 10,
		Ssl: false,
		All: all,
		Fingerprints: data,
		Verbose: verbose,
	}

	wg := new(sync.WaitGroup)

	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			for hostEntry := range hostEntrys {

				if all {
					service := Identify(hostEntry.Host, hostEntry.CNames, o, "", Fingerprints{})
					if service != "" {
						gologger.Info().Label(service).Msgf(hostEntry.Host)
						hostEntry.TakeOver = true
						uniqueMap[hostEntry.Host] = hostEntry
					}

					if service == "" && o.Verbose {
						gologger.Info().Label("[Not Vulnerable]").Msgf(hostEntry.Host)
					}

				} else {
					// 仅测试 cname 匹配的 url
					if ok, cname, fingerprint := VerifyCNAME(hostEntry.CNames, o.Fingerprints); ok {
						service := Identify(hostEntry.Host, hostEntry.CNames, o, cname, fingerprint)
						if service != "" {
							gologger.Info().Label(service).Msgf(hostEntry.Host)
							hostEntry.TakeOver = true
							uniqueMap[hostEntry.Host] = hostEntry
						}

						if service == "" && o.Verbose {
							gologger.Info().Label("[Not Vulnerable]").Msgf(hostEntry.Host)
						}

					}
				}
			}
			wg.Done()
		}()
	}

	for _, result := range uniqueMap {
		hostEntrys <- result
		fmt.Println(result)
	}

	close(hostEntrys)
	wg.Wait()

	return uniqueMap
}
