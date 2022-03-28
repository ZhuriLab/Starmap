package device

import (
	"context"
	"github.com/ZhuriLab/Starmap/pkg/util"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/projectdiscovery/gologger"
	"net"
	"time"
)

func AutoGetDevices() *EtherTable {
	domain := util.RandomStr(4) + ".i.hacking8.com"
	signal := make(chan *EtherTable)
	devices, err := pcap.FindAllDevs()
	if err != nil {
		gologger.Fatal().Msgf("获取网络设备失败:%s\n", err.Error())
	}
	data := make(map[string]net.IP)
	keys := []string{}
	for _, d := range devices {
		for _, address := range d.Addresses {
			ip := address.IP
			if ip.To4() != nil && !ip.IsLoopback() {
				data[d.Name] = ip
				keys = append(keys, d.Name)
			}
		}
	}
	ctx := context.Background()
	// 在初始上下文的基础上创建一个有取消功能的上下文
	ctx, cancel := context.WithCancel(ctx)
	for _, drviceName := range keys {
		go func(drviceName string, domain string, ctx context.Context) {
			var (
				snapshot_len int32         = 1024
				promiscuous  bool          = false
				timeout      time.Duration = -1 * time.Second
				handle       *pcap.Handle
			)
			var err error
			handle, err = pcap.OpenLive(
				drviceName,
				snapshot_len,
				promiscuous,
				timeout,
			)
			if err != nil {
				gologger.Error().Msgf("pcap打开失败:%s\n", err.Error())
				return
			}
			defer handle.Close()
			// Use the handle as a packet source to process all packets
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for {
				select {
				case <-ctx.Done():
					return
				default:
					packet, err := packetSource.NextPacket()
					if err != nil {
						continue
					}
					if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
						dns, _ := dnsLayer.(*layers.DNS)
						if !dns.QR {
							continue
						}
						for _, v := range dns.Questions {
							if string(v.Name) == domain {
								ethLayer := packet.Layer(layers.LayerTypeEthernet)
								if ethLayer != nil {
									eth := ethLayer.(*layers.Ethernet)
									etherTable := EtherTable{
										SrcIp:  data[drviceName],
										Device: drviceName,
										SrcMac: SelfMac(eth.DstMAC),
										DstMac: SelfMac(eth.SrcMAC),
									}
									signal <- &etherTable
									return
								}
							}
						}
					}
				}
			}
		}(drviceName, domain, ctx)
	}
	for {
		select {
		case c := <-signal:
			cancel()
			return c
		default:
			_, _ = net.LookupHost(domain)
			time.Sleep(time.Second * 1)
		}
	}
}
func GetIpv4Devices() (keys []string, data map[string]net.IP) {
	devices, err := pcap.FindAllDevs()
	data = make(map[string]net.IP)
	if err != nil {
		gologger.Fatal().Msgf("获取网络设备失败:%s\n", err.Error())
	}
	for _, d := range devices {
		for _, address := range d.Addresses {
			ip := address.IP
			if ip.To4() != nil && !ip.IsLoopback() {
				gologger.Print().Msgf("  [%d] Name: %s\n", len(keys), d.Name)
				gologger.Print().Msgf("  Description: %s\n", d.Description)
				gologger.Print().Msgf("  Devices addresses: %s\n", d.Description)
				gologger.Print().Msgf("  IP address: %s\n", ip)
				gologger.Print().Msgf("  Subnet mask: %s\n\n", address.Netmask.String())
				data[d.Name] = ip
				keys = append(keys, d.Name)
			}
		}
	}
	return
}
func PcapInit(devicename string) (*pcap.Handle, error) {
	var (
		snapshot_len int32 = 1024
		//promiscuous  bool  = false
		err     error
		timeout time.Duration = -1 * time.Second
	)
	handle, err := pcap.OpenLive(devicename, snapshot_len, false, timeout)
	if err != nil {
		gologger.Fatal().Msgf("pcap初始化失败:%s\n", err.Error())
		return nil, err
	}
	return handle, nil
}
