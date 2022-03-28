package subTakeOver

import (
	"crypto/tls"
	"github.com/valyala/fasthttp"
	"time"
)

func get(url string, ssl bool, timeout int) (body []byte) {
	req := fasthttp.AcquireRequest()
	req.SetRequestURI(site(url, ssl))
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
	req.Header.Add("Connection", "close")
	resp := fasthttp.AcquireResponse()

	client := &fasthttp.Client{TLSConfig: &tls.Config{InsecureSkipVerify: true}}
	err := client.DoTimeout(req, resp, time.Duration(timeout)*time.Second)

	if err != nil {
		return nil
	}

	return resp.Body()
}

func site(url string, ssl bool) (site string) {
	site = "http://" + url
	if ssl {
		site = "https://" + url
	}

	return site
}
