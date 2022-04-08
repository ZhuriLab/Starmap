// Package fofa logic
package fofa

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/ZhuriLab/Starmap/pkg/subscraping"
	"github.com/ZhuriLab/Starmap/pkg/util"
	jsoniter "github.com/json-iterator/go"
	"strconv"
	"strings"
)

type fofaResponse struct {
	Error   bool     		`json:"error"`
	ErrMsg  string   		`json:"errmsg"`
	Size    int      		`json:"size"`
	Results []interface{} 	`json:"results"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		if session.Keys.FofaUsername == "" || session.Keys.FofaSecret == "" {
			return
		}

		// fofa api doc https://fofa.info/static_pages/api_help
		qbase64 := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("domain=\"%s\"", domain)))
		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://fofa.info/api/v1/search/all?full=true&fields=host,ip,port&page=1&size=10000&email=%s&key=%s&qbase64=%s", session.Keys.FofaUsername, session.Keys.FofaSecret, qbase64))
		if err != nil && resp == nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var response fofaResponse
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		if response.Error {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s", response.ErrMsg)}
			return
		}


		if response.Size > 0 {
			subdomains := make(map[string][]string)

			ipPortsTmp := make(map[string][]int)
			for _, result := range response.Results {

				tmp := fmt.Sprintf("%v", result)
				tmp = strings.ReplaceAll(tmp, "[", "")
				tmp = strings.ReplaceAll(tmp, "]", "")

				res := strings.Split(tmp, " ")

				subdomain := res[0]
				if strings.HasPrefix(strings.ToLower(subdomain), "http://") || strings.HasPrefix(strings.ToLower(subdomain), "https://") {
					subdomain = subdomain[strings.Index(subdomain, "//")+2:]
				}
				port, _ := strconv.Atoi(res[2])

				if !util.InInt(port, ipPortsTmp[res[1]]) {
					ipPortsTmp[res[1]] = append(ipPortsTmp[res[1]], port)
				}

				subdomains[subdomain] = append(subdomains[subdomain], res[1])
			}

			for subdomain, ips := range subdomains {
				ipPorts := make(map[string][]int)
				for _, ip := range ips {
					ipPorts[ip] = ipPortsTmp[ip]
				}

				results <- subscraping.Result{
					Source: s.Name(),
					Type: subscraping.Subdomain,
					Value: subdomain,
					IpPorts: ipPorts,
				}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "fofa"
}
