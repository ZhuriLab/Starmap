package main

import (
	"context"
	"fmt"
	"github.com/ZhuriLab/Starmap/pkg/passive"
	"github.com/ZhuriLab/Starmap/pkg/resolve"
	"github.com/ZhuriLab/Starmap/pkg/runner"
	"log"
)

/**
  @author: yhy
  @since: 2022/8/17
  @desc: //TODO
**/

func Starmap(domain string) (error, *map[string]resolve.HostEntry, []string) {
	config, _ := runner.UnmarshalRead("/Users/yhy/.config/Starmap/config.yaml")

	config.Recursive = resolve.DefaultResolvers
	config.Sources = passive.DefaultSources
	config.AllSources = passive.DefaultAllSources
	config.Recursive = passive.DefaultRecursiveSources

	var verify bool

	options := &runner.Options{
		Threads:            10,                              // Thread controls the number of threads to use for active enumerations
		Timeout:            30,                              // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10,                              // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		Resolvers:          resolve.DefaultResolvers,        // Use the default list of resolvers by marshaling it to the config
		Sources:            passive.DefaultSources,          // Use the default list of passive sources
		AllSources:         passive.DefaultAllSources,       // Use the default list of all passive sources
		Recursive:          passive.DefaultRecursiveSources, // Use the default list of recursive sources

		YAMLConfig:     config, // 读取自定义配置文件
		All:            true,
		Verbose:        verify,
		Brute:          true,
		Verify:         true,  // 验证找到的域名
		RemoveWildcard: true,  // 泛解析过滤
		MaxIps:         100,   // 爆破时如果超出一定数量的域名指向同一个 ip，则认为是泛解析
		DNS:            "cn",  // dns 服务器区域选择，根据目标选择不同区域得到的结果不同，国内网站的话，选择 cn，dns 爆破结果比较多
		BruteWordlist:  "",    // 爆破子域的域名字典，不填则使用内置的
		Level:          2,     // 枚举几级域名，默认为二级域名
		LevelDic:       "",    // 枚举多级域名的字典文件，当level大于2时候使用，不填则会默认
		Takeover:       false, // 子域名接管检测
		SAll:           false, // 子域名接管检测中请求全部 url，默认只对匹配的 cname 进行检测
	}

	runnerInstance, err := runner.NewRunner(options)

	err, uniqueMap, unanswers := runnerInstance.EnumerateSingleDomain(context.Background(), domain, nil)

	if err != nil {
		return err, nil, nil
	}

	return nil, uniqueMap, unanswers
}

func main() {
	err, subdomains, unanswers := Starmap("moresec.cn")

	if err != nil { // 运行失败，丢给其他机器扫描
		log.Fatalln(err)
	}

	for _, hostEntry := range *subdomains {
		fmt.Printf("%v \n", hostEntry)
		//delete(*subdomains, sub)
	}

	//*subdomains = nil

	fmt.Println(len(*subdomains))
	fmt.Println(unanswers)
}
