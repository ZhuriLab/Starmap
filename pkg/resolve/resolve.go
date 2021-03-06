package resolve

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/rs/xid"
)


// ResolutionPool is a pool of resolvers created for resolving subdomains
// for a given host.
type ResolutionPool struct {
	*Resolver
	Tasks          chan HostEntry
	Results        chan Result
	wg             *sync.WaitGroup
	removeWildcard bool

	wildcardIPs map[string]struct{}
}

// HostEntry defines a host with the source
type HostEntry struct {
	Host   		string 				`json:"host"`
	Source 		string 				`json:"source"`
	IpPorts     map[string][]int	`json:"ip_ports"`
	CNames  	[]string			`json:"cnames"`
	TakeOver 	bool				`json:"take_over"`
}

// Result contains the result for a host resolution
type Result struct {
	Type   ResultType
	Host   string
	IP     string
	Error  error
	Source string
}

// ResultType is the type of result found
type ResultType int

// Types of data result can return
const (
	Subdomain ResultType = iota
	Error
)

//// NewResolutionPool creates a pool of resolvers for resolving subdomains of a given domain
//func (r *Resolver) NewResolutionPool(workers int, removeWildcard bool) *ResolutionPool {
//	resolutionPool := &ResolutionPool{
//		Resolver:       r,
//		Tasks:          make(chan HostEntry),
//		Results:        make(chan Result),
//		wg:             &sync.WaitGroup{},
//		removeWildcard: removeWildcard,
//		wildcardIPs:    make(map[string]struct{}),
//	}
//
//	go func() {
//		for i := 0; i < workers; i++ {
//			resolutionPool.wg.Add(1)
//			go resolutionPool.resolveWorker()
//		}
//		resolutionPool.wg.Wait()
//		close(resolutionPool.Results)
//	}()
//
//	return resolutionPool
//}

// InitWildcards inits the wildcard ips array
func InitWildcards(r *Resolver, domain string, resolvers []string, maxWildcardChecks int) (error, map[string]struct{}) {
	// 随机多少个域名
	if maxWildcardChecks == 0 {
		maxWildcardChecks = len(resolvers)*2
	}

	wildcardIPs := make(map[string]struct{})
	for i := 0; i < maxWildcardChecks; i++ {
		rand.Seed(time.Now().UTC().UnixNano())
		uid := xid.New().String()

		hosts, _ := r.DNSClient.Lookup(uid + "." + domain)

		if len(hosts) == 0 {
			return fmt.Errorf("%s is not a wildcard domain", domain), nil
		}
		// Append all wildcard ips found for domains
		// Append all wildcard ips found for domains
		for _, host := range hosts {
			wildcardIPs[host] = struct{}{}
		}
	}
	return nil, wildcardIPs
}

//func (r *ResolutionPool) resolveWorker() {
//	for task := range r.Tasks {
//		if !r.removeWildcard {
//			r.Results <- Result{Type: Subdomain, Host: task.Host, IP: "", Source: task.Source}
//			continue
//		}
//
//		fmt.Println(task)
//		hosts, err := r.DNSClient.Lookup(task.Host)
//		if err != nil {
//			r.Results <- Result{Type: Error, Host: task.Host, Source: task.Source, Error: err}
//			continue
//		}
//
//		if len(hosts) == 0 {
//			continue
//		}
//
//		var skip bool
//		for _, host := range hosts {
//			// Ignore the host if it exists in wildcard ips map
//			if _, ok := r.wildcardIPs[host]; ok {
//				skip = true
//				break
//			}
//		}
//
//		if !skip {
//			r.Results <- Result{Type: Subdomain, Host: task.Host, IP: hosts[0], Source: task.Source}
//		}
//	}
//	r.wg.Done()
//}
