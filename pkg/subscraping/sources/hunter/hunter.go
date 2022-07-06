package hunter

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/ZhuriLab/Starmap/pkg/subscraping"
	jsoniter "github.com/json-iterator/go"
)

type hunterResults struct {
	Code int `json:"code"`
	Data struct {
		AccountType string `json:"account_type"`
		Total       int    `json:"total"`
		Time        int    `json:"time"`
		Arr         []struct {
			IsRisk         string `json:"is_risk"`
			URL            string `json:"url"`
			IP             string `json:"ip"`
			Port           int    `json:"port"`
			WebTitle       string `json:"web_title"`
			Domain         string `json:"domain"`
			IsRiskProtocol string `json:"is_risk_protocol"`
			Protocol       string `json:"protocol"`
			BaseProtocol   string `json:"base_protocol"`
			StatusCode     int    `json:"status_code"`
			Component      []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"component"`
			Os        string `json:"os"`
			Company   string `json:"company"`
			Number    string `json:"number"`
			Country   string `json:"country"`
			Province  string `json:"province"`
			City      string `json:"city"`
			UpdatedAt string `json:"updated_at"`
			IsWeb     string `json:"is_web"`
			AsOrg     string `json:"as_org"`
			Isp       string `json:"isp"`
			Banner    string `json:"banner"`
		} `json:"arr"`
		ConsumeQuota string `json:"consume_quota"`
		RestQuota    string `json:"rest_quota"`
		SyntaxPrompt string `json:"syntax_prompt"`
	} `json:"data"`
	Message string `json:"message"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	go func() {
		defer close(results)

		if session.Keys.Hunter == "" {
			return
		}

		// hunter api doc https://hunter.qianxin.com/home/helpCenter?r=5-1-2
		api := "https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=%d&page_size=100&is_web=3&start_time=\"%d-01-01+00:00:00\"&end_time=\"%d-12-31+00:00:00\""

		qbase64 := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("domain=\"%s\"", domain)))

		url := fmt.Sprintf(api, session.Keys.Hunter, qbase64, 1, time.Now().Year()-1, time.Now().Year())

		resp, err := session.SimpleGet(ctx, url)

		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var response hunterResults
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		if response.Code != 200 {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s", response.Message)}
			return
		}

		if response.Data.Total > 0 {
			page := response.Data.Total/100 + 1

			for i := 0; i < page; i++ {
				for _, hunterDomain := range response.Data.Arr {
					subdomain := hunterDomain.Domain
					if subdomain != "" {

						ipPorts := make(map[string][]int)
						ipPorts[hunterDomain.IP] = []int{hunterDomain.Port}

						results <- subscraping.Result{
							Source:  s.Name(),
							Type:    subscraping.Subdomain,
							Value:   subdomain,
							IpPorts: ipPorts,
						}
					}

				}
			}

		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "hunter"
}
