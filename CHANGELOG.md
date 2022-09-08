# Changelog

## v0.2.0
- [feat] 增加dns域传送尝试
- [feat] 尝试内存优化
- [fix] 修复向关闭的 channel 发送数据导致程序异常退出

## v0.1.1
- [feat] 增加 henter、quake

## v0.1.0
- [fix] 修复一处 goroutine 泄露

## v0.0.9
- [fix] 修复泛解析时 map 没有初始化的 bug

## v0.0.8
- [feat] 优化泛解析，添加参数 mI, 爆破时如果超出一定数量的域名指向同一个 ip，则认为是泛解析(默认 100)

## v0.0.7
- [fix] 修复静默模式下还会输出 banner 的 bug

## v0.0.6
- [fix] 修复-s 指定源不生效的 bug
- [feat] 网络空间引擎搜集子域时，同时获取子域的 ip、 开放的端口
  - [x]  shodan
  - [x]  fofa
  - [x]  zoomeyeapi
  
- 主动爆破、泛解析过滤改为默认不使用，使用时请添加 -b/-rW 参数

## v0.0.5
- 子域名爆破时泛解析过滤
    -   参考 https://github.com/boy-hack/ksubdomain/issues/5

## v0.0.4
- 修复修改二进制文件名可能读取不到配置文件的 bug

## v0.0.3
- 参考 [subjack](https://github.com/haccer/subjack) 添加子域名接管检测
- 合并 [subfinder](https://github.com/projectdiscovery/subfinder) v2.5.0

## v0.0.2
- [subfinder](https://github.com/projectdiscovery/subfinder) 和 [ksubdomain](https://github.com/boy-hack/ksubdomain) 初步融合

