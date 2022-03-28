package assets

import _ "embed"

//文件的内容嵌入为slice of byte，也就是一个字节数组

//go:embed fingerprints.json
var Fingerprints []byte

