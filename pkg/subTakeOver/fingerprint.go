package subTakeOver

import (
	"bytes"
	"strings"
)

type Fingerprints struct {
	Service     string   `json:"service"`
	Cname       []string `json:"cname"`
	Fingerprint []string `json:"fingerprint"`
	Nxdomain    bool     `json:"nxdomain"`
	CheckAll    bool     `json:"checkall"`
}


/*
* Triage step to check whether the CNAME matches
* the fingerprinted CNAME of a vulnerable cloud service.
 */

func VerifyCNAME(cnames []string, fingerprints []Fingerprints) (match bool, cname string, fingerprint Fingerprints) {

	match = false
	if len(cname) == 0 {
		return match, "", Fingerprints{}
	}

	cname = cnames[len(cnames)-1]
VERIFY:
	for n := range fingerprints {
		for c := range fingerprints[n].Cname {
			if strings.Contains(cname, fingerprints[n].Cname[c]) {
				match = true
				fingerprint = fingerprints[n]
				break VERIFY
			}
		}
	}

	return match, cname, fingerprint
}

/*
* This function aims to identify whether the subdomain
* is attached to a vulnerable cloud service and able to
* be taken over.
 */
func Identify(subdomain string, cnames []string, o *Options, cname string, fingerprint Fingerprints) (service string) {

	if cname == "" {
		if len(cnames) > 0 {
			cname = cnames[len(cnames)-1]
		}
	}

	if len(cname) <= 3 {
		cname = ""
	}

	//nx := nxdomain(subdomain)
	//
	//if nx {
	//	dead := available.Domain(cname)
	//	if dead {
	//		service = "Domain Available - " + cname
	//		return service
	//	}
	//
	//	// 报告存在 NXDOMAIN 的子域名
	//	// Option to always print the CNAME and not check if it's available to be registered.
	//	if o.Manual && cname != "" {
	//		service = "Dead Domain - " + cname
	//		return service
	//	}
	//}

	if o.Ssl != true && fingerprint.Service == "cloudfront" {
		o.Ssl = true
	}

	body := get(subdomain, o.Ssl, o.Timeout)

	// 只对匹配的 cname 进行检测, 前面已经检测过 cname 匹配了，这里直接进行 body 内容匹配
	if !o.All {
		// 如果字典中的 nxdomain 为 ture(这种情况时，对应指纹字典中没有 fingerprint)
		//只会进行 cname 指纹匹配, 命中则可以进行子域名接管
		if fingerprint.Nxdomain {
			return fingerprint.Service
		}

		if body == nil {
			return ""
		}

		for n := range fingerprint.Fingerprint {
			if bytes.Contains(body, []byte(fingerprint.Fingerprint[n])) {
				return fingerprint.Service
			}
		}
	} else {
		fingerprints := o.Fingerprints

		for f := range fingerprints {	// 不看 cname ，只对 body 内容进行检测

			if fingerprints[f].Nxdomain {
				for n := range fingerprints[f].Cname {
					if strings.Contains(cname, fingerprints[f].Cname[n]) {
						return fingerprints[f].Service
					}
				}
			}

			if body == nil {
				return ""
			}

			if o.Ssl != true && fingerprints[f].Service == "cloudfront" {
				o.Ssl = true
				body = get(subdomain, o.Ssl, o.Timeout)
				if body == nil {
					return ""
				}
			}

			if fingerprints[f].CheckAll {		// 指纹中指定 CheckAll ，cname 、body 内容都检查
				for c := range fingerprints[f].Cname {
					if strings.Contains(cname, fingerprints[f].Cname[c]) {
						//  cname 匹配的情况下 ，再检测cname 对应的指纹是否匹配
						for n := range fingerprints[f].Fingerprint {
							if bytes.Contains(body, []byte(fingerprints[f].Fingerprint[n])) {
								return fingerprints[f].Service
							}
						}
					}

				}
			} else {
				for n := range fingerprints[f].Fingerprint {
					if bytes.Contains(body, []byte(fingerprints[f].Fingerprint[n])) {
						return fingerprints[f].Service
					}
				}
			}
		}

	}

	return ""
}
