package main

import (
	"regexp"
	"testing"
)

func TestValidIPv4(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.0", true},
		{" 192.168.1.1 ", true}, // 允许前后空格
		{"0.0.0.0", true},
		{"abc", false},
		{"256.0.0.0", false},
		{"192.168.1.1/24", false}, // 不接受 CIDR
		{"fe80::1", false},        // 非 IPv4
	}
	for _, c := range cases {
		if got := ValidIPv4(c.in); got != c.want {
			t.Errorf("ValidIPv4(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestValidNetmask(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"255.255.255.0", true},
		{"255.255.0.0", true},
		{"0.0.0.0", true},
		{"255.255.255.1", false}, // 非连续 1
		{"1.2.3.4", false},
		{"256.0.0.0", false},
	}
	for _, c := range cases {
		if got := ValidNetmask(c.in); got != c.want {
			t.Errorf("ValidNetmask(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSubnetOf(t *testing.T) {
	cases := []struct {
		ip, mask, want string
	}{
		{"192.168.1.10", "255.255.255.0", "192.168.1.0/24"},
		{"10.10.10.5", "255.255.0.0", "10.10.0.0/16"},
		{"172.16.5.30", "255.255.255.252", "172.16.5.28/30"},
		{"bad", "255.255.255.0", ""}, // 非法 IP
		{"10.0.0.1", "bad", ""},      // 非法掩码
	}
	for _, c := range cases {
		if got := SubnetOf(c.ip, c.mask); got != c.want {
			t.Errorf("SubnetOf(%q,%q) = %q, want %q", c.ip, c.mask, got, c.want)
		}
	}
}

func TestSplitLines(t *testing.T) {
	got := SplitLines("a\nb\n\nc\r\nd \n")
	want := []string{"a", "b", "c", "d"}
	if len(got) != len(want) {
		t.Fatalf("SplitLines len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("SplitLines[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestJoinComma(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"a", "", "b"}, "a,b"},
		{[]string{" x ", "y"}, "x,y"},
		{nil, ""},
	}
	for _, c := range cases {
		if got := JoinComma(c.in); got != c.want {
			t.Errorf("JoinComma(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNextIPv4(t *testing.T) {
	cases := []struct {
		ip   string
		n    int
		want string
		ok   bool
	}{
		{"192.168.1.10", 1, "192.168.1.11", true},
		{"192.168.1.255", 1, "192.168.2.0", true}, // 跨段进位
		{"10.0.0.0", 256, "10.0.1.0", true},
		{"256.0.0.0", 1, "", false}, // 非法输入
	}
	for _, c := range cases {
		got, ok := nextIPv4(c.ip, c.n)
		if ok != c.ok || got != c.want {
			t.Errorf("nextIPv4(%q,%d) = (%q,%v), want (%q,%v)", c.ip, c.n, got, ok, c.want, c.ok)
		}
	}
}

func TestIntersect(t *testing.T) {
	cases := []struct {
		lists [][]string
		want  []string
	}{
		{nil, nil},
		{[][]string{{"a"}}, []string{"a"}},
		{[][]string{{"a", "b", "c"}, {"b", "c", "d"}}, []string{"b", "c"}},
		{[][]string{{"a", "b", "c"}, {"b", "c", "d"}, {"c", "e"}}, []string{"c"}},
	}
	for _, c := range cases {
		if got := intersect(c.lists...); !equalSlice(got, c.want) {
			t.Errorf("intersect(%v) = %v, want %v", c.lists, got, c.want)
		}
	}
}

func TestGroupByHostID(t *testing.T) {
	groups := []NodeIfaces{
		{NodeID: "host-1", NodeName: "n1"},
		{NodeID: "host-2", NodeName: "n2"},
	}
	m := groupByHostID(groups)
	if len(m) != 2 {
		t.Fatalf("groupByHostID len = %d, want 2", len(m))
	}
	if m["host-1"].NodeName != "n1" || m["host-2"].NodeName != "n2" {
		t.Errorf("groupByHostID mapping wrong: %+v", m)
	}
}

func TestPhyCandidatesOf(t *testing.T) {
	ni := NodeIfaces{
		NodeID: "host-1",
		Data: []Iface{
			{Name: "bond0", Type: "bond", Members: []string{"eth0"}},
			{Name: "eth0", Type: "phy-iface", Status: 1},                          // 被 bond0 占用, UP
			{Name: "eth1", Type: "phy-iface", Status: 1, Roles: []string{"mgmt"}}, // 被角色占用, UP
			{Name: "eth2", Type: "phy-iface", Status: 2},                          // 空闲, DOWN
		},
	}
	got := phyCandidatesOf(ni)
	if len(got) != 3 {
		t.Fatalf("phyCandidatesOf len = %d, want 3 (%+v)", len(got), got)
	}
	// 排序权重：空闲优先（eth2=1）< 占用（eth0/eth1=2）；占用内部按名称 eth0 < eth1
	wantOrder := []string{"eth2", "eth0", "eth1"}
	for i, name := range wantOrder {
		if got[i].Iface.Name != name {
			t.Errorf("candidate[%d].Name = %q, want %q", i, got[i].Iface.Name, name)
		}
	}
	if got[0].Owner != "" {
		t.Errorf("eth2 should be free, got owner %q", got[0].Owner)
	}
	if got[1].Owner != "bond0" {
		t.Errorf("eth0 owner = %q, want bond0", got[1].Owner)
	}
	if got[2].Owner != "角色 mgmt" {
		t.Errorf("eth1 owner = %q, want 角色 mgmt", got[2].Owner)
	}
}

func TestNewUUIDv4(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		u := NewUUIDv4()
		if !re.MatchString(u) {
			t.Fatalf("NewUUIDv4() = %q, does not match v4 format", u)
		}
		if seen[u] {
			t.Fatalf("NewUUIDv4() collision: %q", u)
		}
		seen[u] = true
	}
}

func TestTruncate(t *testing.T) {
	cases := []struct {
		s    string
		n    int
		want string
	}{
		{"hello", 10, "hello"},   // 不超长不截断
		{"hello", 3, "hel..."},   // 截断并加省略号
		{"中文测试abc", 3, "中文测..."}, // 按 rune 计数，中文不出现乱码
		{"a", 1, "a"},
	}
	for _, c := range cases {
		if got := truncate(c.s, c.n); got != c.want {
			t.Errorf("truncate(%q,%d) = %q, want %q", c.s, c.n, got, c.want)
		}
	}
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
