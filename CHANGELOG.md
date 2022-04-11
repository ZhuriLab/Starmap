# Changelog

## v0.0.7
- [fix] 去除静默模式下 banner 输出

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

