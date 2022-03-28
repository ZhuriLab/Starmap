package device

import (
	"net"
)

type SelfMac net.HardwareAddr

func (d SelfMac) String() string {
	n := (net.HardwareAddr)(d)
	return n.String()
}
func (d SelfMac) MarshalYAML() (interface{}, error) {
	n := (net.HardwareAddr)(d)
	return n.String(), nil
}
func (d SelfMac) HardwareAddr() net.HardwareAddr {
	n := (net.HardwareAddr)(d)
	return n
}


type EtherTable struct {
	SrcIp  net.IP  `yaml:"src_ip"`
	Device string  `yaml:"device"`
	SrcMac SelfMac `yaml:"src_mac"`
	DstMac SelfMac `yaml:"dst_mac"`
}

