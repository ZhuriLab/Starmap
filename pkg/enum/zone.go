package enum

/**
  @author: yhy
  @since: 2022/7/20
  @desc: //TODO
**/
import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/caffix/resolve"
	"github.com/miekg/dns"
)

// DNSAnswer is the type used by Amass to represent a DNS record.
type DNSAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

// DNSRequest handles data needed throughout Service processing of a DNS name.
type DNSRequest struct {
	Name    string
	Domain  string
	Records []DNSAnswer
	Tag     string
	Source  string
}

// ZoneTransfer attempts a DNS zone transfer using the provided server.
// The returned slice contains all the records discovered from the zone transfer.
func ZoneTransfer(sub, domain, server string) ([]*DNSRequest, error) {
	var results []*DNSRequest

	// Set the maximum time allowed for making the connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addr := net.JoinHostPort(server, "53")
	conn, err := DialContext(ctx, "tcp", addr)
	if err != nil {
		return results, fmt.Errorf("zone xfr error: Failed to obtain TCP connection to [%s]: %v", addr, err)
	}
	defer conn.Close()

	xfr := &dns.Transfer{
		Conn:        &dns.Conn{Conn: conn},
		ReadTimeout: 15 * time.Second,
	}

	m := &dns.Msg{}
	m.SetAxfr(dns.Fqdn(sub))

	in, err := xfr.In(m, "")
	if err != nil {
		return results, fmt.Errorf("DNS zone transfer error for [%s]: %v", addr, err)
	}

	for en := range in {
		reqs := getXfrRequests(en, domain)
		if reqs == nil {
			continue
		}

		results = append(results, reqs...)
	}
	return results, nil
}

func getXfrRequests(en *dns.Envelope, domain string) []*DNSRequest {
	if en.Error != nil {
		return nil
	}

	reqs := make(map[string]*DNSRequest)
	for _, a := range en.RR {
		var record DNSAnswer

		switch v := a.(type) {
		case *dns.CNAME:
			record.Type = int(dns.TypeCNAME)
			record.Name = resolve.RemoveLastDot(v.Hdr.Name)
			record.Data = resolve.RemoveLastDot(v.Target)
		case *dns.A:
			record.Type = int(dns.TypeA)
			record.Name = resolve.RemoveLastDot(v.Hdr.Name)
			record.Data = v.A.String()
		case *dns.AAAA:
			record.Type = int(dns.TypeAAAA)
			record.Name = resolve.RemoveLastDot(v.Hdr.Name)
			record.Data = v.AAAA.String()
		case *dns.PTR:
			record.Type = int(dns.TypePTR)
			record.Name = resolve.RemoveLastDot(v.Hdr.Name)
			record.Data = resolve.RemoveLastDot(v.Ptr)
		case *dns.NS:
			record.Type = int(dns.TypeNS)
			record.Name = realName(v.Hdr)
			record.Data = resolve.RemoveLastDot(v.Ns)
		case *dns.MX:
			record.Type = int(dns.TypeMX)
			record.Name = resolve.RemoveLastDot(v.Hdr.Name)
			record.Data = resolve.RemoveLastDot(v.Mx)
		case *dns.TXT:
			record.Type = int(dns.TypeTXT)
			record.Name = resolve.RemoveLastDot(v.Hdr.Name)
			for _, piece := range v.Txt {
				record.Data += piece + " "
			}
		case *dns.SOA:
			record.Type = int(dns.TypeSOA)
			record.Name = resolve.RemoveLastDot(v.Hdr.Name)
			record.Data = v.Ns + " " + v.Mbox
		case *dns.SPF:
			record.Type = int(dns.TypeSPF)
			record.Name = resolve.RemoveLastDot(v.Hdr.Name)
			for _, piece := range v.Txt {
				record.Data += piece + " "
			}
		case *dns.SRV:
			record.Type = int(dns.TypeSRV)
			record.Name = resolve.RemoveLastDot(v.Hdr.Name)
			record.Data = resolve.RemoveLastDot(v.Target)
		default:
			continue
		}

		if r, found := reqs[record.Name]; found {
			r.Records = append(r.Records, record)
		} else {
			reqs[record.Name] = &DNSRequest{
				Name:    record.Name,
				Domain:  domain,
				Records: []DNSAnswer{record},
				Tag:     "axfr",
				Source:  "DNS Zone XFR",
			}
		}
	}

	var requests []*DNSRequest
	for _, r := range reqs {
		requests = append(requests, r)
	}
	return requests
}

func realName(hdr dns.RR_Header) string {
	pieces := strings.Split(hdr.Name, " ")

	return resolve.RemoveLastDot(pieces[len(pieces)-1])
}

var LocalAddr net.Addr

// DialContext performs the dial using global variables (e.g. LocalAddr).
func DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{DualStack: true}

	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(p)
	if err != nil {
		return nil, err
	}

	if LocalAddr != nil {
		addr, _, err := net.ParseCIDR(LocalAddr.String())

		if err == nil && strings.HasPrefix(network, "tcp") {
			d.LocalAddr = &net.TCPAddr{
				IP:   addr,
				Port: port,
			}
		} else if err == nil && strings.HasPrefix(network, "udp") {
			d.LocalAddr = &net.UDPAddr{
				IP:   addr,
				Port: port,
			}
		}
	}

	return d.DialContext(ctx, network, addr)
}
