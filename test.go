package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/ZhuriLab/Starmap/pkg/passive"
	"github.com/ZhuriLab/Starmap/pkg/resolve"
	"github.com/ZhuriLab/Starmap/pkg/runner"
	"io"
	"io/ioutil"
	"log"
)

// 作为 go library 集成
func main() {
	// 自定义配置文件位置
	config, _ := runner.UnmarshalRead("/Users/yhy/.config/Starmap/config.yaml")

	config.Recursive = resolve.DefaultResolvers
	config.Sources = passive.DefaultSources
	config.AllSources = passive.DefaultAllSources
	config.Recursive = passive.DefaultRecursiveSources

	options := &runner.Options {
		Threads:            10, // Thread controls the number of threads to use for active enumerations
		Timeout:            30, // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10, // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		Resolvers:          resolve.DefaultResolvers, // Use the default list of resolvers by marshaling it to the config
		Sources:            passive.DefaultSources, // Use the default list of passive sources
		AllSources:         passive.DefaultAllSources, // Use the default list of all passive sources
		Recursive:          passive.DefaultRecursiveSources,	// Use the default list of recursive sources

		YAMLConfig:         config,	// 读取自定义配置文件
		All: 				true,
		Verbose: 			true,
		Brute:				true,
		Verify:             true,	// 验证找到的域名
		RemoveWildcard: 	true,	// 泛解析过滤
		Silent: 			false,	// 是否为静默模式，只输出找到的域名
		DNS: 				"cn",	// dns 服务器区域选择，根据目标选择不同区域得到的结果不同，国内网站的话，选择 cn，dns 爆破结果比较多
		BruteWordlist:      "",		// 爆破子域的域名字典，不填则使用内置的
		Level: 				2,		// 枚举几级域名，默认为二级域名
		LevelDic:           "",		// 枚举多级域名的字典文件，当level大于2时候使用，不填则会默认
		Takeover: 			false,	// 子域名接管检测
		SAll: 				false,  // 子域名接管检测中请求全部 url，默认只对匹配的 cname 进行检测
	}

	options.ConfigureOutput()

	runnerInstance, err := runner.NewRunner(options)

	buf := bytes.Buffer{}
	err, subdomains := runnerInstance.EnumerateSingleDomain(context.Background(), "baidu.com", []io.Writer{&buf})
	if err != nil {
		log.Fatal(err)
	}

	data, err := ioutil.ReadAll(&buf)
	if err != nil {
		log.Fatal(err)
	}

	// 只输出域名
	fmt.Printf("%s", data)

	// 输出详细信息
	/*
		Host   	string 		`json:"host"`
		Source 	string 		`json:"source"`
		Ips    	[]string	`json:"ips"`
		CNames  []string	`json:"cnames"`
		TakeOver 	bool		`json:"take_over"`
	*/
	for _, result := range subdomains {
		fmt.Println(result.Source, result.Host, result.Ips, result.CNames, result.TakeOver)
	}
}