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
	uniqueMap, _ = Enum("baidu.com", uniqueMap, false, "", 2, "", resolvers, nil, 30)
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

	uniqueMap, _ = Verify(uniqueMap, true, resolvers, nil, 30)
	for k, v := range uniqueMap {
		fmt.Println(k, v)
	}
}
