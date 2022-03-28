package active

import (
	"github.com/google/gopacket/layers"
)

// RecvResult 接收结果数据结构
type RecvResult struct {
	Subdomain 		string
	Answers   		[]layers.DNSResourceRecord
	ResponseCode 	layers.DNSResponseCode
}
