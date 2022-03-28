package active

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/projectdiscovery/gologger"
	"sync/atomic"
	"time"
)

func (r *runner) recvChanel(ctx context.Context) error {
	var (
		snapshotLen = 65536
		timeout     = -1 * time.Second
		err         error
	)
	inactive, err := pcap.NewInactiveHandle(r.ether.Device)
	if err != nil {
		return errors.New(fmt.Sprintf("pcap.NewInactiveHandle:%s", err.Error()))
	}
	err = inactive.SetSnapLen(snapshotLen)
	if err != nil {
		return errors.New(fmt.Sprintf("inactive.SetSnapLen:%s", err.Error()))
	}
	defer inactive.CleanUp()
	if err = inactive.SetTimeout(timeout); err != nil {
		return errors.New(fmt.Sprintf("inactive.SetTimeout:%s", err.Error()))
	}
	err = inactive.SetImmediateMode(true)
	if err != nil {
		return err
	}
	handle, err := inactive.Activate()
	if err != nil {
		return errors.New(fmt.Sprintf("inactive.Activate():%s", err.Error()))
	}
	defer handle.Close()

	err = handle.SetBPFFilter(fmt.Sprintf("udp and src port 53 and dst port %d", r.freeport))
	if err != nil {
		return errors.New(fmt.Sprintf("SetBPFFilter Faild:%s", err.Error()))
	}

	// Listening

	var udp layers.UDP
	var dns layers.DNS
	var eth layers.Ethernet
	var ipv4 layers.IPv4
	var ipv6 layers.IPv6

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet, &eth, &ipv4, &ipv6, &udp, &dns)

	var data []byte
	var decoded []gopacket.LayerType
	for {
		data, _, err = handle.ReadPacketData()
		if err != nil {
			continue
		}
		err = parser.DecodeLayers(data, &decoded)
		if err != nil {
			continue
		}
		if !dns.QR {
			continue
		}
		if dns.ID != r.dnsid {
			continue
		}
		atomic.AddUint64(&r.recvIndex, 1)
		if len(dns.Questions) == 0 {
			continue
		}
		domain := string(dns.Questions[0].Name)

		r.hm.Del(domain)

		if dns.ANCount > 0 {
			atomic.AddUint64(&r.successIndex, 1)
			result := RecvResult {
				Subdomain: domain,
				Answers:   dns.Answers,
				ResponseCode: dns.ResponseCode,
			}

			select {
			case <-ctx.Done():
				gologger.Error().Msg("recvChanel ctx.Done()............")
			default:
				r.recver <- result
			}
		}
	}
}
