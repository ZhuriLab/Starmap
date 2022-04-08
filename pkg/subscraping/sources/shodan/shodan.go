// Package shodan logic
package shodan

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"io"

	"github.com/ZhuriLab/Starmap/pkg/subscraping"
	jsoniter "github.com/json-iterator/go"
)

// Source is the passive scraping agent
type Source struct{}


type respone struct {
	Subdomain string 	`json:"subdomain"`
	Type      string	`json:"type"`
	IP        string    `json:"value"`
	Ports     []int     `json:"ports"`
	Tags      []string  `json:"tags"`
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		if session.Keys.Shodan == "" {
			return
		}
		searchURL := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", domain, session.Keys.Shodan)
		resp, err := session.SimpleGet(ctx, searchURL)
		if err != nil {
			session.DiscardHTTPResponse(resp)
			gologger.Debug().Msg(err.Error())
			return
		}

		body, err := io.ReadAll(resp.Body)
		defer resp.Body.Close()

		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			return
		}

		if jsoniter.Get(body, "error").ToString() != "" {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%v", jsoniter.Get(body, "error").ToString())}
			return
		}

		subdomains := jsoniter.Get(body, "data")

		for i := 0; i < subdomains.Size(); i++ {

			var data respone
			json.Unmarshal([]byte(subdomains.Get(i).ToString()), &data)

			var sub string
			prefix := data.Subdomain
			var (
				ip string
				ports []int
			)

			if prefix != "" {
				sub = prefix + "." + domain
			} else {
				sub = domain
			}

			if data.Type == "A" {
				ip = data.IP
			}

			if data.Ports != nil {
				ports = data.Ports
			}

			ipPorts := make(map[string][]int)
			ipPorts[ip] = ports

			results <- subscraping.Result{
				Source: s.Name(),
				Type: subscraping.Subdomain,
				Value: sub,
				IpPorts: ipPorts,
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "shodan"
}
