package util

import (
	"bufio"
	"github.com/ZhuriLab/Starmap/pkg/resolve"
	"math/rand"
	"os"
	"strings"
	"time"
)


func RandomStr(n int) string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz1234567890")
	rand.Seed(time.Now().UnixNano())
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// LinesInFile 读取文件 返回每行的数组
func LinesInFile(fileName string) ([]string, error) {
	result := []string{}
	f, err := os.Open(fileName)
	if err != nil {
		return result, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			result = append(result, line)
		}
	}
	return result, nil
}

func MergeMap(map1, map2 map[string]resolve.HostEntry) map[string]resolve.HostEntry {
	map3 := make(map[string]resolve.HostEntry)

	for i,v := range map1 {
		for j,w := range map2 {
			if i== j {
				map3[i] = w

			}else{
				if _, ok := map3[i]; !ok {
					map3[i] = v
				}
				if _, ok := map3[j]; !ok {
					map3[j] = w
				}
			}
		}
	}
	return map3
}


func MergeIpPortMap(map1, map2 map[string][]int) map[string][]int {
	map3 := make(map[string][]int)

	for i,v := range map1 {
		for j,w := range map2 {
			if i== j {
				map3[i] = w

			}else{
				if _, ok := map3[i]; !ok {
					map3[i] = v
				}
				if _, ok := map3[j]; !ok {
					map3[j] = w
				}
			}
		}
	}
	return map3
}


// RemoveDuplicateElement  数组去重
func RemoveDuplicateElement(strs []string) []string {
	result := make([]string, 0, len(strs))
	temp := map[string]struct{}{}
	for _, item := range strs {
		if item != "" {
			if _, ok := temp[item]; !ok {
				temp[item] = struct{}{}
				result = append(result, item)
			}
		}

	}
	return result
}


// In 判断一个字符串是否在另一个字符数组里面，存在返回true
func In(target string, strs []string) bool {
	target = strings.TrimSpace(target)
	for _, element := range strs {
		if strings.Contains(target, element) {
			return true
		}
	}
	return false
}

// In 判断一个字符串是否在另一个字符数组里面，存在返回true
func InInt(target int, strs []int) bool {
	for _, element := range strs {
		if target == element {
			return true
		}
	}
	return false
}

