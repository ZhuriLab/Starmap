// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"fmt"
	"testing"
)

// https://github.com/vulhub/vulhub/blob/master/dns/dns-zone-transfer/README.zh-cn.md

func TestZoneTransfer(t *testing.T) {

	a, err := ZoneTransfer("vulhub.org", "", "192.168.102.102")
	if err != nil {
		t.Errorf("Error in creating ZoneTransfer: %v", err)
	}

	for _, out := range a {
		fmt.Printf("name: %s, Source: %s, tag: %s, domain: %s , rec: %v\r\n", out.Name, out.Source, out.Tag, out.Domain, out.Records)
	}
}
