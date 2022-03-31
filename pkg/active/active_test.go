package active

import (
	"fmt"
	"github.com/ZhuriLab/Starmap/pkg/resolve"
	"testing"
)

func TestEnum(t *testing.T) {
	uniqueMap := make(map[string]resolve.HostEntry)
	resolvers := []string{
		"114.114.114.114",
	}
	uniqueMap = Enum("baidu.com", uniqueMap, false,"", 2,"",resolvers, nil)
	for k, v := range uniqueMap {
		fmt.Println(k, v)
	}

}

func TestVerify(t *testing.T) {
	uniqueMap := make(map[string]resolve.HostEntry)

	hostEntry := resolve.HostEntry{Host: "www.baidu.com", Source: ""}

	uniqueMap["www.baidu.com"] = hostEntry

	fmt.Println(uniqueMap)

	resolvers := []string{
		"114.114.114.114",
	}

	uniqueMap = Verify(uniqueMap, true, resolvers, nil)
	for k, v := range uniqueMap {
		fmt.Println(k, v)
	}
}


