package active

import (
	"context"
	"fmt"
	"github.com/ZhuriLab/Starmap/pkg/active/device"
	"github.com/ZhuriLab/Starmap/pkg/active/statusdb"
	"github.com/ZhuriLab/Starmap/pkg/resolve"
	"github.com/ZhuriLab/Starmap/pkg/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/phayes/freeport"
	"github.com/projectdiscovery/gologger"
	"go.uber.org/ratelimit"
	"math"
	"math/rand"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

type runner struct {
	ether           *device.EtherTable //本地网卡信息
	hm              *statusdb.StatusDb
	options         *Options
	limit           ratelimit.Limiter
	handle          *pcap.Handle
	successIndex    uint64
	sendIndex       uint64
	recvIndex       uint64
	faildIndex      uint64
	sender          chan string
	recver          chan RecvResult
	unanswers       []string
	freeport        int
	dnsid           uint16      // dnsid 用于接收的确定ID
	maxRetry        int         // 最大重试次数
	timeout         int64       // 超时xx秒后重试
	fisrtloadChanel chan string // 数据加载完毕的chanel
	startTime       time.Time
	domains         []string
	wildcardIPs     []string
}

func init() {
	rand.Seed(time.Now().Unix())
}

func New(options *Options) (*runner, error) {
	var err error
	r := new(runner)
	r.options = options

	r.options.WildcardIPsAc = make(map[string]struct{})
	r.ether = device.AutoGetDevices()

	r.hm = statusdb.CreateMemoryDB()

	r.handle, err = device.PcapInit(r.ether.Device)
	if err != nil {
		return nil, err
	}

	var subdomainDict []string
	if options.FileName == "" {
		subdomainDict = GetDefaultSubdomainData()
		gologger.Info().Msgf("Load built-in dictionary:%d\n", len(subdomainDict))
	} else {
		subdomainDict, err = util.LinesInFile(options.FileName)
		if err != nil {
			gologger.Fatal().Msgf("打开文件:%s 错误:%s", options.FileName, err.Error())
		}
		gologger.Info().Msgf("Load built-in dictionary: %s \n", options.FileName)
	}

	// 根据发包总数和timeout时间来分配每秒速度
	allPacket := len(subdomainDict)
	if options.Level > 2 {
		allPacket = allPacket * int(math.Pow(float64(len(options.LevelDomains)), float64(options.Level-2)))
	}
	calcLimit := float64(allPacket/options.TimeOut) * 0.85
	if calcLimit < 5000 {
		calcLimit = 5000
	}

	limit := int(math.Min(calcLimit, float64(options.Rate)))

	r.limit = ratelimit.New(limit)       // per second
	r.sender = make(chan string, 99)     // 可多个协程发送
	r.recver = make(chan RecvResult, 99) // 多个协程接收

	freePort, err := freeport.GetFreePort()
	if err != nil {
		return nil, err
	}

	r.freeport = freePort
	r.dnsid = 0x2021 // set dnsid 65500
	r.maxRetry = r.options.Retry

	r.timeout = int64(r.options.TimeOut)
	r.fisrtloadChanel = make(chan string)
	r.startTime = time.Now()

	go func() {
		if options.Method == "enum" {
			for _, prefix := range subdomainDict {
				sub := prefix + "." + r.options.Domain
				r.sender <- sub
				if options.Level > 2 {
					r.iterDomains(options.Level, sub)
				}
			}
		} else if options.Method == "verify" {
			for sub := range r.options.UniqueMap {
				r.sender <- sub
			}
		}

		r.fisrtloadChanel <- "ok"
	}()
	return r, nil
}

func (r *runner) iterDomains(level int, domain string) {
	if level == 2 {
		return
	}
	for _, levelMsg := range r.options.LevelDomains {
		tmpDomain := fmt.Sprintf("%s.%s", levelMsg, domain)
		r.sender <- tmpDomain
		r.iterDomains(level-1, tmpDomain)
	}
}

func (r *runner) choseDns() string {
	resolvers := r.options.Resolvers
	rand.Seed(time.Now().UTC().UnixNano())
	dns := strings.Split(resolvers[rand.Intn(len(resolvers))], ":")[0]
	return dns
}

func (r *runner) PrintStatus() {
	queue := r.hm.Length()
	tc := int(time.Since(r.startTime).Seconds())
	gologger.Info().Msgf("\rSuccess:%d Send:%d Queue:%d Accept:%d Fail:%d Elapsed:%ds", r.successIndex, r.sendIndex, queue, r.recvIndex, r.faildIndex, tc)
}

func (r *runner) RunEnumeration(uniqueMap map[string]resolve.HostEntry, ctx context.Context) (map[string]resolve.HostEntry, map[string]struct{}) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		err := r.recvChanel(ctx, false)
		if err != nil {
			if fmt.Sprint(err) == "Generic error" {
				gologger.Fatal().Msgf("compiled against an old version of libpcap; please compile against libpcap-1.5.0 or later")
			}
			gologger.Error().Msgf("active err: %s", err)
		}

	}() // 启动接收线程

	go r.sendCycle() // 发送线程

	go func(ctx context.Context) {
		ipsMap := make(map[string]int)

		for {
			select {
			case <-ctx.Done():
				return
			case result := <-r.recver:
				var cnames []string
				var ips []string
				// Log the verbose message about the found subdomain per source
				if _, ok := uniqueMap[result.Subdomain]; !ok {
					for _, answers := range result.Answers {
						if answers.Class == layers.DNSClassIN {
							if answers.CNAME != nil {
								cnames = append(cnames, string(answers.CNAME))
							}
							if answers.IP != nil {
								ips = append(ips, answers.IP.String())
							}
						}
					}

					if len(ips) == 0 {
						continue
					}

					/*
						todo 这里只是记录了第一个 ip , 还是应该记录所有解析出的 ip ？
						比如 这个域名 spotifyforbrands.com， 存在泛解析，也只是解析出一个 ip
					*/

					// ip 都记录一下 ，超过阈值，则认为是泛解析 ip
					ipsMap[ips[0]] += 1

					// 记录这个 ip 到泛解析 ip 列表中， 最终在返回结果中去除
					if ipsMap[ips[0]] > r.options.MaxIPs {
						r.options.WildcardIPsAc[ips[0]] = struct{}{}
						continue
					}

					var ipPorts map[string][]int

					if uniqueMap[result.Subdomain].IpPorts != nil {
						ipPorts = uniqueMap[result.Subdomain].IpPorts
					} else {
						ipPorts = make(map[string][]int)
					}

					var skip bool
					for _, ip := range ips {
						// Ignore the host if it exists in wildcard ips map
						if _, ok := r.options.WildcardIPs[ip]; ok {
							skip = true
							break
						}

						if ipPorts[ip] == nil {
							ipPorts[ip] = nil
						}
					}

					// 不是泛解析出的 ip 的记录
					if !skip {
						//todo 应该也返回 dns 的响应
						hostEntry := resolve.HostEntry{
							Host:    result.Subdomain,
							Source:  "DNS Brute Forcing",
							IpPorts: ipPorts,
							CNames:  cnames,
						}
						uniqueMap[result.Subdomain] = hostEntry
						gologger.Info().Msgf("[DNS Brute Forcing] %s %s %s \n", result.Subdomain, cnames, ips)
					}
				}
			}
		}

	}(ctx)

	var isLoadOver = false // 是否加载文件完毕
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			r.PrintStatus()
			if isLoadOver {
				if r.hm.Length() <= 0 {
					return uniqueMap, r.options.WildcardIPsAc
				}
			}
		case <-r.fisrtloadChanel:
			go r.retry(ctx) // 遍历hm，依次重试
			isLoadOver = true
		case <-ctx.Done():
			return uniqueMap, r.options.WildcardIPsAc
		}
	}

}

func (r *runner) RunEnumerationVerify(ctx context.Context) (map[string]resolve.HostEntry, map[string]struct{}, []string) {
	AuniqueMap := make(map[string]resolve.HostEntry)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		err := r.recvChanel(ctx, true)
		if err != nil {
			gologger.Error().Msgf("active err: %s", err)
			return
		}
	}() // 启动接收线程

	go r.sendCycle() // 发送线程

	go func(ctx context.Context) {

		ipsMap := make(map[string]int)
		for {
			select {
			case <-ctx.Done():
				return
			case result := <-r.recver:
				var cnames []string
				var ips []string

				for _, answers := range result.Answers {
					if answers.CNAME != nil {
						cnames = append(cnames, string(answers.CNAME))
					}
					if answers.IP != nil {
						ips = append(ips, answers.IP.String())
					}
				}

				if len(ips) == 0 {
					continue
				}

				// ip 都记录一下 ，超过阈值，则认为是泛解析 ip
				ipsMap[ips[0]] += 1

				// 记录这个 ip 到泛解析 ip 列表中， 最终在返回结果中去除
				if ipsMap[ips[0]] > r.options.MaxIPs {
					r.options.WildcardIPsAc[ips[0]] = struct{}{}
					continue
				}

				var ipPorts map[string][]int

				if r.options.UniqueMap[result.Subdomain].IpPorts != nil {
					ipPorts = r.options.UniqueMap[result.Subdomain].IpPorts
				} else {
					ipPorts = make(map[string][]int)
				}

				var skip bool
				for _, ip := range ips {
					// Ignore the host if it exists in wildcard ips map
					if _, ok := r.options.WildcardIPs[ip]; ok {
						skip = true
						break
					}

					if ipPorts[ip] == nil {
						ipPorts[ip] = nil
					}

				}

				// 不是泛解析出的 ip 的记录
				if !skip {
					hostEntry := resolve.HostEntry{
						Host:    result.Subdomain,
						Source:  r.options.UniqueMap[result.Subdomain].Source,
						CNames:  cnames,
						IpPorts: ipPorts,
					}

					AuniqueMap[result.Subdomain] = hostEntry
					gologger.Info().Msgf("[dns verify] %s %s %s %s ", result.Subdomain, r.options.UniqueMap[result.Subdomain].Source, cnames, ips)
				}
			}
		}

	}(ctx)

	var isLoadOver = false // 是否加载文件完毕
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			//r.PrintStatus()
			if isLoadOver {
				if r.hm.Length() <= 0 {
					return AuniqueMap, r.options.WildcardIPsAc, r.unanswers
				}
			}
		case <-r.fisrtloadChanel:
			go r.retry(ctx) // 遍历hm，依次重试
			isLoadOver = true
		case <-ctx.Done():
			return AuniqueMap, r.options.WildcardIPsAc, r.unanswers
		}
	}
}

func (r *runner) Close() {
	for sub := range r.options.UniqueMap {
		delete(r.options.UniqueMap, sub)
	}

	// 尝试内存回收
	r.options.UniqueMap = nil
	runtime.GC()
	debug.FreeOSMemory()
	close(r.sender)
	r.handle.Close()
	r.hm.Close()
}
