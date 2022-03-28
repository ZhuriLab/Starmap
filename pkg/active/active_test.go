package active

import (
	"fmt"
	"github.com/ZhuriLab/Starmap/pkg/resolve"
	"testing"
)

func TestEnum(t *testing.T) {
	uniqueMap := make(map[string]resolve.HostEntry)
	uniqueMap = Enum("baidu.com", uniqueMap, false,"", 2,"","cn")
	for k, v := range uniqueMap {
		fmt.Println(k, v)
	}

}

func TestVerify(t *testing.T) {
	uniqueMap := make(map[string]resolve.HostEntry)

	hostEntry := resolve.HostEntry{Host: "www.baidu.com", Source: ""}

	uniqueMap["www.baidu.com"] = hostEntry

	fmt.Println(uniqueMap)

	uniqueMap = Verify(uniqueMap, true, "cn")
	for k, v := range uniqueMap {
		fmt.Println(k, v)
	}

}


