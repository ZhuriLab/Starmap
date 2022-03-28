package subTakeOver


//func nxdomain(subdomain string) bool {
//	// initialize global pseudo random generators
//	rand.Seed(time.Now().UTC().UnixNano())
//
//	c := dns.Client{}
//	m := dns.Msg{}
//
//	dnsService := DefaultBaselineResolvers[rand.Intn(len(DefaultBaselineResolvers))]
//
//	m.SetQuestion(dns.Fqdn(subdomain), dns.TypeNS)
//	r, _, err := c.Exchange(&m, dnsService + ":53")
//
//	if err != nil {
//		return false
//	}
//
//	if strings.Contains(r.String(), "NXDOMAIN") {
//		return true
//	}
//
//	return false
//}

