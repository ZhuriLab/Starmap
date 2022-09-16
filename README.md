# 🌟 Starmap

![Starmap](https://socialify.git.ci/ZhuriLab/Starmap/image?description=1&font=Inter&forks=1&issues=1&logo=https%3A%2F%2Favatars.githubusercontent.com%2Fu%2F69614236%3Fs%3D200%26v%3D4&name=1&owner=1&pattern=Circuit%20Board&pulls=1&stargazers=1&theme=Light)

- [Amass](https://github.com/OWASP/Amass/) 虽然搜集的方法多，但太笨重，不方便集成，目标多了会内存爆炸
- [subfinder](https://github.com/projectdiscovery/subfinder) 非常方便集成，但是只有被动的方式
- [ksubdomain](https://github.com/boy-hack/ksubdomain) 仅主动爆破，以及验证

遂以 subfinder 为基础，融合 ksubdomain、 Amass 的一些优点进行二次开发的一款子域名收集工具，可以很方便作为 go 库集成进入项目中。并增加了以下功能：

-   子域名接管检测功能
-   网络空间扫描引擎被动获取子域时，增加ip、端口开放收集
    -   shodan 	获取 ip\端口
    -   fofa       获取 ip\端口
    -   zoomeyeapi 获取 ip

# 🍺 Installation
下载二进制 https://github.com/ZhuriLab/Starmap/releases

安装`libpcap`环境 
- Windows 下载 npcap 驱动: https://npcap.com/#download (ksubdomain 推荐下载的winpcap驱动存在一点问题，我在虚拟机中跑不出任何东西，改用 npcap 驱动可以)
- Linux 已经静态编译打包`libpcap`，无需其他操作
- MacOS 自带`libpcap`,无需其他操作 

# 🔅 Usage

1. 被动模式运行并保存到文件（只保存域名）

    ```bash
    Starmap -d baidu.com -o res.txt
    ```

2. 被动加主动爆破, 过滤泛解析 json 格式输出（json 输出更丰富）

    ```bash
    Starmap -d baidu.com -b -rW -oJ -o res.json
    ```
    
3. 其他选项

   ```bash
   Flags:
   INPUT:
        -d, -domain string[]  domains to find subdomains for
        枚举的目标域名
        -dL, -list string  file containing list of domains for subdomain discovery
        枚举的域名列表的文件
   
   SOURCE:
        -s, -sources string[]  specific sources to use for discovery (-s crtsh,github)
        被动使用的源
        -recursive  use only recursive sources
        仅使用递归源
        -all  Use all sources (slow) for enumeration
        使用所有源进行枚举
        -es, -exclude-sources string[]  sources to exclude from enumeration (-es archiveis,zoomeye)
         被动枚举中排除使用的源列表
   
   OUTPUT:
        -o, -output string  file to write output to
        输出文件名
        -oJ, -json  write output in JSONL(ines) format
        Json格式输出，该选项输出内容丰富,输出到文件需要配合 -o res.json
   
   CONFIGURATION:
        -config string  flag config file
        自定义API密钥等的配置文件位置 (default "/Users/用户名/.config/Starmap/config.yaml")
        -proxy string  http proxy to use with subfinder
        指定被动api获取子域名时的代理
   
   DEBUG:
        -silent  show only subdomains in output
        使用后屏幕将仅输出结果域名
        -version  show version of Starmap
        输出当前版本
        -v  show verbose output
        显示详细输出
   
   DNS BRUTE FORCING SUBDOMAIN:
        -w string  Path to a different wordlist file for brute forcing
        dns 爆破使用的字典
        -ld string  Multilevel subdomain dictionary(level > 2 use)
        dns 枚举多级域名的字典文件，当level大于2时候使用，不填则会默认
        -l int  Number of blasting subdomain layers
        枚举几级域名，默认为二级域名 (default 2)
        -n int  Number of DNS forced subdomains
        dns爆破每个域名的次数，默认跑一次 (default 1)
        -brute  Use DNS brute forcing subdomain(default false)
        被动加 dns 主动爆破(默认不使用)
        -verify  DNS authentication survival, Export only verified domain names
        验证被动获取的域名，使用后仅输出验证存活的域名
        -dns string  DNS server, cn:China dns, in:International, all:(cn+in DNS), conf:(read ./config/Starmap/config.yaml), Select according to the target. 
        DNS服务器，默认国内的服务器(cn)(cn: 表示使用国内的 dns, in:国外 dns，all: 全部内置 dns, conf: 从配置文件 ./config/Starmap/config.yaml获取)，根据目标选择 (default "cn")
        -rW, -active  Domain name pan resolution filtering
        爆破时过滤泛解析(default false)
        -mW int  Number of random domain names during universal resolution detection(default len(resolvers)*2)
        泛解析检测时的随机域名数量(default len(resolvers)*2)
   
   SUBDOMAIN TAKEOVER:
        -takeover   Scan subdomain takeover (default False).
        子域名接管检测 (默认：false)
        -sa  subdomain take over: Request to test each URL (by default, only the URL matching CNAME is requested to test).
        子域名接管检测：请求测试每个URL（默认情况下，仅请求测试与CNAME匹配的URL）
   ```

# 🎉 Starmap Go library

```go
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
	"path/filepath"
	"os/user"

)

func userHomeDir() string {
	usr, err := user.Current()
	if err != nil {
		log.Print("Could not get user home directory: %s\n", err)
	}
	return usr.HomeDir
}

// 作为 go library 集成
func main() {

	config, _ := runner.UnmarshalRead(filepath.Join(userHomeDir(), ".config/Starmap/config.yaml"))

	config.Recursive = resolve.DefaultResolvers
	config.Sources = passive.DefaultSources
	config.AllSources = passive.DefaultAllSources
	config.Recursive = passive.DefaultRecursiveSources

	options := &runner.Options{
		Threads:            10, // Thread controls the number of threads to use for active enumerations
		Timeout:            30, // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10, // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		Resolvers:          resolve.DefaultResolvers, // Use the default list of resolvers by marshaling it to the config
		Sources:            passive.DefaultSources, // Use the default list of passive sources
		AllSources:         passive.DefaultAllSources, // Use the default list of all passive sources
		Recursive:          passive.DefaultRecursiveSources,	// Use the default list of recursive sources

		YAMLConfig:         config,	// 读取自定义配置文件
		All: 				true,
		Verbose: 			false,
		Brute:				true,
		Verify:             true,	// 验证找到的域名 
		RemoveWildcard: 	true,	// 泛解析过滤 
		MaxIps:             100,    // 爆破时如果超出一定数量的域名指向同一个 ip，则认为是泛解析
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
	Host   		string 				`json:"host"`
	Source 		string 				`json:"source"`
	IpPorts     map[string][]int	`json:"ip_ports"`
	CNames  	[]string			`json:"cnames"`
	TakeOver 	bool				`json:"take_over"`
	*/
	for _, result := range subdomains {
		fmt.Println(result.Source, result.Host, result.IpPorts, result.CNames, result.TakeOver)
	}
}
```

# 📌 TODO

- [ ] [Amass](https://github.com/OWASP/Amass/) 中的子域名检测技术
- [x] 子域名接管检测

# 💡 Tips
 - 指定不同的 dns ，获取到的结果会不同。比如：如果目标是国内的网站，选择国内的 dns 得到的子域名结果可能会比较多
 - 提示 `pcap打开失败:vnic0: You don't have permission to capture on that device ((cannot open BPF device) /dev/bpf0: Permission denied)`等错误
   
    执行`sudo chmod 777 /dev/bpf*` 或 `sudo ./Starmap`

# 👀 参考
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [ksubdomain](https://github.com/boy-hack/ksubdomain)
- [Amass](https://github.com/OWASP/Amass)

#  📄 免责声明
本工具仅面向合法授权的企业安全建设行为，在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，作者将不承担任何法律及连带责任。

在使用本工具前，请您务必审慎阅读、充分理解各条款内容，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。 除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。