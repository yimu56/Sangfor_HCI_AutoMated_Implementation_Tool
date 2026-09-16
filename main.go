// sangfor-ifaces: 深信服设备 vapi 接口客户端 —— 桌面图形界面版（Walk / Win32）
//
// 登录协议（由 登录抓包.har + 设备前端 login.js 逆向还原）:
//  1. GET  /login                                  从页面提取 RSA 公钥 RSAModulus (e=10001)
//  2. POST /vapi/json/access/srand   username=xxx  (触发会话，data.salt 供 UKey 流程使用)
//  3. GET  /vapi/json/access/secret                返回 data.secret
//  4. POST /vapi/json/access/privacy/check         username=xxx&join=1
//  5. POST /vapi/extjs/access/ticket               password = RSA_PKCS1v15(明文密码 + secret)
//     响应 data.CSRFPreventionToken 即 CSRF 令牌，
//     同时 Set-Cookie: LoginAuthCookie=<ticket>
//  6. 后续所有 /vapi 请求需同时携带:
//     Cookie: LoginAuthCookie=<ticket 值>
//     CSRFPreventionToken: <data.CSRFPreventionToken>
//     （HAR 导出通常会过滤 Cookie 头，仅看 HAR 会漏掉这一关键点）
//
// 查询接口:
//
//	GET /vapi/json/cluster/nodelist                              集群节点列表
//	GET /vapi/json/cluster/network/ifaces?node_id=xxx&refresh=1  各节点网口信息
//	GET /vapi/extjs/cluster/vms?group_type=group&scene=resources_used  虚拟机列表
//	GET /vapi/extjs/nodes/<hostid>/info                          节点硬件信息
//
// VXLAN 网络相关（由 VXLAN网络.har 抓包还原，实测 6 节点 VXLAN 集群）:
//
//	GET /vapi/json/cluster/network/ifaces          不带 node_id 时一次返回全集群网口，
//	                                               按节点分组 [{node_name,node_id,node_status,data:[...]}]，
//	                                               可 1 次请求替代"逐节点 N 次请求"（网口信息页已改用此方式）
//	GET /vapi/json/cluster/network/mgmt-ifaces     管理网口（bond/teaming 口 + 集群 IP 别名），
//	                                               扁平数组，每个元素自带 node_name/node_id
//	GET /vapi/json/cluster/network/vxlan-ifaces    VXLAN 网口（隧道承载口，role 含 "vxlan"，
//	                                               带 vxlan_mtu 与 vxlan[] 承载地址信息）
//
// 修改网口（写操作，来自 修改网络接口.har）:
//
//  1. POST /vapi/extjs/vs/vs_config/verfity_passwd   password=RSA_PKCS1v15(明文密码)
//     （注意：此处不拼接 secret，已实测确认）
//  2. PUT  /vapi/json/nodes/<hostid>/network/ifaces/<iface>
//     desc=&ip=&netmask=&gateway=&link_mode=6&mtu=1500&mac=<mac>&custom_name=
//     → 返回 data.task_id
//  3. GET  /vapi/json/log/process?upid=<task_id>     轮询任务（process=0 表示进行中）
//
// GUI 说明:
//   - 登录成功后自动刷新 节点/网口/虚拟机/硬件 数据
//   - 修改网口配置页面: 选择节点 -> 选择网口 -> 修改字段 -> 预览变更 -> 确认提交
//   - 修改网口跳过密码二次校验（VerifyPassword），直接提交，后续人工验证
//   - 会话与上次输入默认值缓存在可执行文件同目录（.sangfor-session.json / .sangfor-lastinput.json）
//
// 历史命令行版保留在 main_cli_backup.go，需要可自行取回。
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lxn/walk"
	"github.com/lxn/win"
)

// ---------- 通用响应封装 ----------

// APIResponse 对应 vapi 的通用返回结构
type APIResponse struct {
	Success        int              `json:"success"`
	ErrcodeTracing string           `json:"errcode_tracing"`
	Data           *json.RawMessage `json:"data"`
	Errcode        *string          `json:"errcode"`
}

// ---------- 登录相关 ----------

// SecretData /vapi/json/access/secret 响应
type SecretData struct {
	Secret string `json:"secret"`
}

// TicketData /vapi/extjs/access/ticket 响应
type TicketData struct {
	CSRFPreventionToken string `json:"CSRFPreventionToken"`
	UserRole            string `json:"user_role"`
	Username            string `json:"username"`
	Cluster             string `json:"cluster"`
}

// ---------- 节点列表 ----------

// ClusterNode /vapi/json/cluster/nodelist 返回的节点
type ClusterNode struct {
	Hostid      string `json:"hostid"`
	Node        string `json:"node"`
	IP          string `json:"ip"`
	Status      string `json:"status"`
	Master      int    `json:"master"`
	HostProtect int    `json:"host_protect"`
}

// ---------- 网口信息 ----------

// NodeIfaces /vapi/json/cluster/network/ifaces 返回的单个节点分组
type NodeIfaces struct {
	NodeName       string  `json:"node_name"`
	NodeID         string  `json:"node_id"`
	NodeStatus     int     `json:"node_status"`
	SriovVtdEnable int     `json:"sriov_vtd_enable"`
	Data           []Iface `json:"data"`
}

// Iface 单个网口
type Iface struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	CustomName      string    `json:"custom_name"`
	Type            string    `json:"type"`
	MAC             string    `json:"mac"`
	IP              string    `json:"ip"`
	Netmask         string    `json:"netmask"`
	Gateway         string    `json:"gateway"`
	MTU             int       `json:"mtu"`
	Status          int       `json:"status"` // 1=UP, 2=DOWN
	Enable          int       `json:"enable"`
	IfaceMode       string    `json:"iface_mode"` // kernel / dpdk
	DriverType      string    `json:"driver_type"`
	PCIAddress      string    `json:"pci_address"`
	Roles           []string  `json:"role"`
	LinkMode        int       `json:"link_mode"`            // 链路模式（各网卡取值不同，见 autoLinkMode）
	Media           string    `json:"media"`                // "autonegotiation" 表示当前为自动协商
	SupportedModes  []int     `json:"supported_link_modes"` // 该网卡支持的模式列表
	BDRSwitch       string    `json:"bdrSwitch"`
	Desc            string    `json:"desc"`
	FirmwareVersion string    `json:"firmware_version"`
	Speed           Speed     `json:"speed"`
	Primary         []Primary `json:"primary"`

	// ---- 以下字段来自 VXLAN网络.har（vxlan-ifaces / mgmt-ifaces / 无参 ifaces）----
	// 注意: vxlan-ifaces 与 mgmt-ifaces 返回的是【扁平数组】，每个元素自带 node_* 字段；
	//       无参 ifaces 返回的是【按节点分组】结构，分组里的网口不带 node_*（用外层的即可）。
	NodeName     string      `json:"node_name"`    // 所属节点管理 IP
	NodeID       string      `json:"node_id"`      // 所属节点 hostid
	NodeStatus   int         `json:"node_status"`  // 节点状态: 1=正常
	NodeProtect  int         `json:"node_protect"` // 节点保护
	Mode         string      `json:"mode"`         // bond 工作模式（如 lacp-layer34）
	Members      []string    `json:"members"`      // bond 成员口名称
	MemberInfo   []Iface     `json:"member_info"`  // bond 成员口详情
	Alias        []Primary   `json:"alias"`        // 别名 IP（如集群 IP: role=cluster_ip）
	AliasRole    string      `json:"alias_role"`
	DisasterRole int         `json:"disaster_role"` // 容灾角色
	VXLANMTU     int         `json:"vxlan_mtu"`     // VXLAN 承载 MTU（比物理口 MTU 大，两者要配套）
	VXLAN        []VXLANInfo `json:"vxlan"`         // VXLAN 承载地址信息
}

// VXLANInfo 网口上的 VXLAN 承载信息（vxlan[] 数组元素）
type VXLANInfo struct {
	Gateway string `json:"gateway"`
	IP      string `json:"ip"`
	Netmask string `json:"netmask"`
	MAC     string `json:"mac"`
	MTU     int    `json:"mtu"`
}

// Speed 网口速率。
// 注意: Negotiation 是"是否自动协商"的开关(1=自动协商, 0=强制)，不是链路模式编号，
// 切勿把它当成 link_mode 提交（曾因此把网口设成 10M）。
//
// 坑: 同一字段在不同接口里形态不同（已实测）——
//   - /cluster/network/ifaces（含分组与 vxlan/mgmt-ifaces 顶层）：对象
//     {"negotiation":1,"value":1000,"unknow":0,"duplex":2}
//   - mgmt-ifaces 的 member_info[].speed：纯数字 1000
//
// 因此自定义反序列化，两种都能吃；若只按对象解析，GetMgmtIfaces 会整体解析失败。
type Speed struct {
	Negotiation int `json:"negotiation"`
	Value       int `json:"value"` // Mbps, 0=未协商
	Duplex      int `json:"duplex"`
}

func (s *Speed) UnmarshalJSON(b []byte) error {
	t := strings.TrimSpace(string(b))
	if t == "" || t == "null" {
		*s = Speed{}
		return nil
	}
	// 纯数字 / 带引号的数字: 视为速率值（其余字段缺省）
	if t[0] != '{' {
		t2 := strings.Trim(t, `"`)
		if n, err := strconv.Atoi(t2); err == nil {
			*s = Speed{Value: n}
			return nil
		}
		*s = Speed{}
		return nil
	}
	// 对象形态: 用别名类型避免递归调用本方法
	type rawSpeed Speed
	var r rawSpeed
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	*s = Speed(r)
	return nil
}

// Primary 主 IP
type Primary struct {
	IP      string `json:"ip"`
	Netmask string `json:"netmask"`
	Role    string `json:"role"`
}

// ---------- 虚拟机列表 ----------

// VMGroup /vapi/extjs/cluster/vms 返回的分组
type VMGroup struct {
	Name        string `json:"name"`
	Owner       string `json:"owner"`
	DirectVMNum int    `json:"direct_vm_num"`
	Data        []VM   `json:"data"`
}

// VM 单台虚拟机（仅保留关键字段，响应含 100+ 字段）
type VM struct {
	Name           string `json:"name"`
	VMID           int64  `json:"vmid"`
	Status         string `json:"status"`        // running / shutdown ...
	ActualStatus   string `json:"actual_status"` // 实际运行状态
	CPUs           int    `json:"cpus"`          // vCPU 数
	MemTotal       int64  `json:"mem_total"`     // 字节
	MemUsed        int64  `json:"mem_used"`      // 字节
	DiskTotal      int64  `json:"disk_total"`    // 字节
	DiskUsed       int64  `json:"disk_used"`     // 字节
	CPURatio       string `json:"cpu_ratio"`
	MemRatio       string `json:"mem_ratio"`
	OSDistribution string `json:"os_distribution"`
	GuestHostname  string `json:"guest_hostname"`
	Groupname      string `json:"groupname"`
	Storagename    string `json:"storagename"`
	Node           string `json:"node"`
	HostConfig     string `json:"host_config"`
	UUID           string `json:"uuid"`
	VMType         string `json:"vmtype"`
	CreateTime     int64  `json:"create_time"` // unix 秒
	Netin          int64  `json:"netin"`
	Netout         int64  `json:"netout"`
}

// RunningStatus 是否运行中
func (v VM) RunningStatus() bool {
	return v.Status == "running" || v.ActualStatus == "running"
}

// ---------- 硬件信息 ----------

// HostInfo /vapi/extjs/nodes/<hostid>/info 返回的节点硬件信息
type HostInfo struct {
	Name         string `json:"name"`
	IP           string `json:"ip"`
	Status       string `json:"status"`
	SerialNumber string `json:"serial_number"`
	ServerModel  string `json:"server_model"`
	HardwareType string `json:"hardware_type"`
	OSVersion    string `json:"os_version"`
	Uptime       int64  `json:"uptime"` // 秒
	RunningVMs   int    `json:"running_vms"`
	ControlRole  int    `json:"control_role"`

	CPUStatus struct {
		CPUModel string `json:"type"`
		Sockets  int    `json:"sockets"`
		Cores    int    `json:"cores"`
		Threads  int    `json:"cpu_threads"`
		Mhz      string `json:"mhz"`
		Cache    string `json:"cache_size"`
		Ratio    string `json:"ratio"`
		Vendor   string `json:"vendor_id"`
		Temps    []struct {
			Name  string `json:"name"`
			Value int    `json:"value"`
		} `json:"temperatures"`
	} `json:"cpu_status"`

	MemStatus struct {
		Total int64  `json:"total"`
		Free  int64  `json:"free"`
		Ratio string `json:"ratio"`
	} `json:"mem_status"`

	MemLayout struct {
		Compute struct {
			ConfTotalByte    int64 `json:"conf_total_byte"`
			OverusedByte     int64 `json:"overused_byte"`
			PreallocatedByte int64 `json:"preallocated_byte"`
			OverusableByte   int64 `json:"overusable_byte"`
			ConfOverPercent  int   `json:"conf_over_percent"`
		} `json:"compute"`
	} `json:"mem_layout"`

	ConfCPU struct {
		Enable         int    `json:"enable"`
		ConfTotalVcore int    `json:"conf_total_vcore"`
		ConfUsedVcore  int    `json:"conf_used_vcore"`
		TotalCPUVcore  int    `json:"total_cpu_vcore"`
		CPUOverPercent int    `json:"cpu_over_percent"`
		ConfUsedRate   string `json:"conf_used_rate"`
	} `json:"conf_cpu"`

	ConfMemStatus struct {
		BaseTotalByte int64 `json:"base_total_byte"`
		BaseUsedByte  int64 `json:"base_used_byte"`
		ConfTotalByte int64 `json:"conf_total_byte"`
		ConfUsedByte  int64 `json:"conf_used_byte"`
	} `json:"conf_mem_status"`

	StorageStatus []struct {
		Name   string `json:"name"`
		Type   string `json:"type"`
		ID     string `json:"id"`
		Total  int64  `json:"total"`
		Used   int64  `json:"used"`
		Free   int64  `json:"free"`
		Ratio  string `json:"ratio"`
		Status int    `json:"status"`
	} `json:"storage_status"`

	RaidCardStatus map[string]struct {
		ControllerModel string `json:"controller_model"`
		ControllerStat  string `json:"controller_status"`
		PhysicalDevNum  string `json:"physical_dev_num"`
	} `json:"raid_card_status"`

	NetCardsStatus struct {
		Num   int `json:"net_cards_num"`
		Array []struct {
			Type string `json:"type"`
		} `json:"net_card_array"`
	} `json:"net_cards_status"`

	Fan []struct {
		Name   string `json:"name"`
		Speed  int    `json:"speed"`
		Status string `json:"status"`
	} `json:"fan"`

	Power []struct {
		ModelName string `json:"model_name"`
		Vendor    string `json:"vendor"`
		SerialNum string `json:"serial_number"`
	} `json:"power"`
}

// GetHostInfo 获取指定节点硬件信息
func (c *Client) GetHostInfo(hostID string) (*HostInfo, error) {
	path := "/vapi/extjs/nodes/" + url.QueryEscape(hostID) + "/info"
	raw, err := c.callAPI(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var info HostInfo
	if err := json.Unmarshal(*raw, &info); err != nil {
		return nil, fmt.Errorf("解析硬件信息失败: %w", err)
	}
	return &info, nil
}

// ---------- 修改网口配置（写操作） ----------

// IfaceConfig 修改网口时提交的配置
type IfaceConfig struct {
	Desc       string // 备注
	IP         string
	Netmask    string
	Gateway    string
	LinkMode   string // 双工/速率，抓包为 6（自动协商）
	MTU        string
	MAC        string // 必填，取自当前网口信息
	CustomName string
}

// flexString 兼容 JSON 里的字符串或数字（设备同一字段有时返回 "0" 有时返回 0）
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	*f = flexString(strings.Trim(string(b), `"`))
	return nil
}

// TaskStatus /vapi/json/log/process 返回的任务状态
type TaskStatus struct {
	Message        flexString `json:"message"`
	Process        flexString `json:"process"`
	ErrcodeTracing string     `json:"errcode_tracing"`
}

// isRunning 任务是否仍在执行
func (t TaskStatus) isRunning() bool {
	p := string(t.Process)
	return p == "" || p == "0"
}

// VerifyPassword 校验当前登录账号的密码。
// 抓包与实测确认: password = RSA_PKCS1v15(明文密码)，不拼接 secret。
// 注: GUI 版修改网口默认跳过此步骤（直接提交，人工验证），此方法保留备用。
func (c *Client) VerifyPassword(pass string) error {
	if c.rsaKey == nil {
		mod, err := c.fetchRSAModulus()
		if err != nil {
			return fmt.Errorf("获取 RSA 公钥失败: %w", err)
		}
		if c.rsaKey, err = parseRSAPublicKey(mod); err != nil {
			return err
		}
	}
	enc, err := rsaEncryptPKCS1v15(c.rsaKey, pass)
	if err != nil {
		return fmt.Errorf("密码加密失败: %w", err)
	}
	raw, err := c.callAPI(http.MethodPost, "/vapi/extjs/vs/vs_config/verfity_passwd",
		url.Values{"password": {enc}})
	if err != nil {
		return fmt.Errorf("密码校验失败: %w", err)
	}
	var res string
	if err := json.Unmarshal(*raw, &res); err != nil || res != "OK" {
		return fmt.Errorf("密码校验未通过: %s", truncate(string(*raw), 100))
	}
	return nil
}

// SetIface 修改指定节点网口配置（危险写操作），返回异步任务 ID
func (c *Client) SetIface(nodeID, iface string, cfg IfaceConfig) (string, error) {
	path := "/vapi/json/nodes/" + url.QueryEscape(nodeID) + "/network/ifaces/" + url.PathEscape(iface)
	raw, err := c.callAPI(http.MethodPut, path, url.Values{
		"desc":        {cfg.Desc},
		"ip":          {cfg.IP},
		"netmask":     {cfg.Netmask},
		"gateway":     {cfg.Gateway},
		"link_mode":   {cfg.LinkMode},
		"mtu":         {cfg.MTU},
		"mac":         {cfg.MAC},
		"custom_name": {cfg.CustomName},
	})
	if err != nil {
		return "", fmt.Errorf("提交网口修改失败: %w", err)
	}
	var res struct {
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal(*raw, &res); err != nil {
		return "", fmt.Errorf("解析任务 ID 失败: %w", err)
	}
	if res.TaskID == "" {
		return "", errors.New("未返回任务 ID")
	}
	return res.TaskID, nil
}

// WaitTask 轮询异步任务直到完成或超时
func (c *Client) WaitTask(taskID string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	lastMsg := ""
	for time.Now().Before(deadline) {
		raw, err := c.callAPI(http.MethodGet,
			"/vapi/json/log/process?upid="+url.QueryEscape(taskID), nil)
		if err != nil {
			return lastMsg, err
		}
		var st TaskStatus
		if err := json.Unmarshal(*raw, &st); err != nil {
			return lastMsg, fmt.Errorf("解析任务状态失败: %w", err)
		}
		if st.Message != "" {
			lastMsg = string(st.Message)
		}
		if !st.isRunning() {
			return lastMsg, nil
		}
		time.Sleep(2 * time.Second)
	}
	return lastMsg, errors.New("等待任务完成超时（任务可能仍在后台执行，请到设备界面确认）")
}

// ---------- HTTP 客户端 ----------

type Client struct {
	baseURL  string
	token    string // CSRFPreventionToken
	cookie   string // LoginAuthCookie=<ticket>（登录后由 Set-Cookie 获得）
	pass     string // 当前账号密码（内存持有，写操作校验用，避免二次输入）
	rsaKey   *rsa.PublicKey
	http     *http.Client
	username string // 登录用户名
	role     string // 登录角色
}

func NewClient(host string) *Client {
	return &Client{
		baseURL: "https://" + host,
		http: &http.Client{
			Timeout: 30 * time.Second,
			// 深信服设备: 自签名证书 + 不支持 TLS 1.3（仅 TLS 1.2 + RSA 套件）
			Transport: &http.Transport{
				Proxy: nil, // 直连设备，忽略环境代理设置
				TLSClientConfig: &tls.Config{ //nolint:gosec
					InsecureSkipVerify: true,
					MinVersion:         tls.VersionTLS12,
					MaxVersion:         tls.VersionTLS12,
					CipherSuites: []uint16{
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					},
				},
			},
		},
	}
}

// do 发送请求并返回响应体与响应头
func (c *Client) do(method, path string, form url.Values) ([]byte, http.Header, error) {
	var bodyReader io.Reader
	if form != nil {
		bodyReader = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, nil, err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "zh_CN")
	req.Header.Set("Referer", c.baseURL+"/login")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	if c.token != "" {
		req.Header.Set("CSRFPreventionToken", c.token)
	}
	if c.cookie != "" {
		req.Header.Set("Cookie", c.cookie)
	}
	// 业务查询阶段 Referer 指向主页面（与浏览器行为一致）
	if strings.Contains(path, "/vapi/") && c.cookie != "" {
		req.Header.Set("Referer", c.baseURL+"/")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("请求 %s 失败: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return body, resp.Header, fmt.Errorf("请求 %s 返回 HTTP %d: %s", path, resp.StatusCode, truncate(string(body), 200))
	}
	return body, resp.Header, nil
}

// callAPI 调用 vapi 接口并校验 success=1
func (c *Client) callAPI(method, path string, form url.Values) (*json.RawMessage, error) {
	body, _, err := c.do(method, path, form)
	if err != nil {
		return nil, err
	}
	var api APIResponse
	if err := json.Unmarshal(body, &api); err != nil {
		return nil, fmt.Errorf("解析 %s 响应失败: %w, body=%s", path, err, truncate(string(body), 200))
	}
	if api.Success != 1 {
		return nil, fmt.Errorf("请求 %s 业务失败: success=%d errcode=%v tracing=%s",
			path, api.Success, derefStr(api.Errcode), api.ErrcodeTracing)
	}
	return api.Data, nil
}

// ---------- 登录 ----------

// fetchRSAModulus 从登录页 HTML 提取 RSA 公钥模数
func (c *Client) fetchRSAModulus() (string, error) {
	body, _, err := c.do(http.MethodGet, "/login", nil)
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`RSAModulus\s*:\s*"([0-9a-fA-F]+)"`)
	m := re.FindSubmatch(body)
	if m == nil {
		return "", errors.New("登录页中未找到 RSAModulus")
	}
	return string(m[1]), nil
}

// parseRSAPublicKey 将 hex 模数 + 指数 10001 组装为 RSA 公钥
func parseRSAPublicKey(modulusHex string) (*rsa.PublicKey, error) {
	nb, err := hex.DecodeString(modulusHex)
	if err != nil {
		return nil, fmt.Errorf("RSAModulus 非法: %w", err)
	}
	n := new(big.Int).SetBytes(nb)
	return &rsa.PublicKey{N: n, E: 65537}, nil
}

// rsaEncryptPKCS1v15 与前端一致: PKCS#1 v1.5 填充后 RSA 加密, 输出小写 hex
func rsaEncryptPKCS1v15(pub *rsa.PublicKey, plaintext string) (string, error) {
	ct, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(plaintext))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ct), nil
}

// Login 自动登录, 成功后 token/cookie 保存在 Client 中
func (c *Client) Login(user, pass string) error {
	// 1. 提取 RSA 公钥
	mod, err := c.fetchRSAModulus()
	if err != nil {
		return fmt.Errorf("获取 RSA 公钥失败: %w", err)
	}
	pub, err := parseRSAPublicKey(mod)
	if err != nil {
		return err
	}
	c.rsaKey = pub

	// 2. srand（触发会话；salt 仅 UKey 流程使用，这里忽略）
	if _, err := c.callAPI(http.MethodPost, "/vapi/json/access/srand",
		url.Values{"username": {user}}); err != nil {
		return fmt.Errorf("srand 失败: %w", err)
	}

	// 3. secret
	raw, err := c.callAPI(http.MethodGet, "/vapi/json/access/secret", nil)
	if err != nil {
		return fmt.Errorf("获取 secret 失败: %w", err)
	}
	var sec SecretData
	if err := json.Unmarshal(*raw, &sec); err != nil || sec.Secret == "" {
		return fmt.Errorf("解析 secret 失败: %w", err)
	}

	// 4. 密码加密: RSA(明文密码 + secret)
	encPwd, err := rsaEncryptPKCS1v15(pub, pass+sec.Secret)
	if err != nil {
		return fmt.Errorf("密码加密失败: %w", err)
	}

	// 5. privacy/check（前端与 ticket 并行提交, 这里先行调用, 失败不阻断）
	_, _ = c.callAPI(http.MethodPost, "/vapi/json/access/privacy/check",
		url.Values{"username": {user}, "join": {"1"}})

	// 6. ticket（响应含 CSRFPreventionToken 与 Set-Cookie: LoginAuthCookie）
	body, hdr, err := c.do(http.MethodPost, "/vapi/extjs/access/ticket", url.Values{
		"username": {user},
		"password": {encPwd},
		"hardware": {""},
		"certinfo": {""},
		"secret":   {sec.Secret},
	})
	if err != nil {
		return fmt.Errorf("登录失败: %w", err)
	}
	var api APIResponse
	if err := json.Unmarshal(body, &api); err != nil {
		return fmt.Errorf("解析 ticket 响应失败: %w", err)
	}
	if api.Success != 1 || api.Data == nil {
		return fmt.Errorf("登录失败: success=%d body=%s", api.Success, truncate(string(body), 200))
	}
	var tk TicketData
	if err := json.Unmarshal(*api.Data, &tk); err != nil {
		return fmt.Errorf("解析 ticket 数据失败: %w", err)
	}
	if tk.CSRFPreventionToken == "" {
		return errors.New("登录响应中未包含 CSRFPreventionToken")
	}
	c.token = tk.CSRFPreventionToken
	c.pass = pass // 记住密码，写操作校验时自动使用
	c.username = tk.Username
	c.role = tk.UserRole

	// 提取 LoginAuthCookie（会话凭证，后续请求必须携带）
	for _, sc := range hdr.Values("Set-Cookie") {
		if strings.HasPrefix(sc, "LoginAuthCookie=") {
			c.cookie = strings.Split(sc, ";")[0]
			break
		}
	}
	if c.cookie == "" {
		return errors.New("登录响应中未包含 LoginAuthCookie")
	}
	return nil
}

// Logout 登出（尽力而为）
func (c *Client) Logout() {
	if c.token == "" {
		return
	}
	_, _ = c.callAPI(http.MethodPost, "/vapi/extjs/access/logout", url.Values{})
}

// ---------- 业务查询 ----------

// GetNodeList 获取集群节点列表
func (c *Client) GetNodeList() ([]ClusterNode, error) {
	raw, err := c.callAPI(http.MethodGet, "/vapi/json/cluster/nodelist", nil)
	if err != nil {
		return nil, err
	}
	var nodes []ClusterNode
	if err := json.Unmarshal(*raw, &nodes); err != nil {
		return nil, fmt.Errorf("解析节点列表失败: %w", err)
	}
	return nodes, nil
}

// GetIfaces 获取指定节点的网口信息（响应 data 为数组，取第一个元素）
func (c *Client) GetIfaces(nodeID string) (*NodeIfaces, error) {
	path := "/vapi/json/cluster/network/ifaces?node_id=" + url.QueryEscape(nodeID) + "&refresh=1"
	raw, err := c.callAPI(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var list []NodeIfaces
	if err := json.Unmarshal(*raw, &list); err != nil {
		return nil, fmt.Errorf("解析网口信息失败: %w", err)
	}
	if len(list) == 0 {
		return nil, errors.New("网口信息为空")
	}
	return &list[0], nil
}

// GetAllIfaces 一次性获取【全集群所有节点】的网口信息。
//
// 实测（VXLAN网络.har）：同一个 /cluster/network/ifaces 接口，
// 不带 node_id 时返回按节点分组的数组，元素结构与 GetIfaces 完全一致。
// 因此可用 1 次请求替代"先拉节点列表再逐节点拉网口"的 N+1 次请求。
func (c *Client) GetAllIfaces() ([]NodeIfaces, error) {
	raw, err := c.callAPI(http.MethodGet, "/vapi/json/cluster/network/ifaces", nil)
	if err != nil {
		return nil, err
	}
	var list []NodeIfaces
	if err := json.Unmarshal(*raw, &list); err != nil {
		return nil, fmt.Errorf("解析全集群网口信息失败: %w", err)
	}
	return list, nil
}

// getFlatIfaces 拉取"扁平数组 + 自带 node_* 字段"的网口接口（vxlan-ifaces / mgmt-ifaces）
func (c *Client) getFlatIfaces(path, what string) ([]Iface, error) {
	raw, err := c.callAPI(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var list []Iface
	if err := json.Unmarshal(*raw, &list); err != nil {
		return nil, fmt.Errorf("解析%s失败: %w", what, err)
	}
	return list, nil
}

// GetMgmtIfaces 获取全部节点的管理网口（bond/teaming 口、集群 IP 别名）
func (c *Client) GetMgmtIfaces() ([]Iface, error) {
	return c.getFlatIfaces("/vapi/json/cluster/network/mgmt-ifaces", "管理网口")
}

// GetVXLANIfaces 获取全部节点的 VXLAN 网口（隧道承载口，role 含 "vxlan"）
func (c *Client) GetVXLANIfaces() ([]Iface, error) {
	return c.getFlatIfaces("/vapi/json/cluster/network/vxlan-ifaces", "VXLAN 网口")
}

// GetVMList 获取虚拟机列表（按分组返回）
func (c *Client) GetVMList() ([]VMGroup, error) {
	path := "/vapi/extjs/cluster/vms?group_type=group&scene=resources_used"
	raw, err := c.callAPI(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var groups []VMGroup
	if err := json.Unmarshal(*raw, &groups); err != nil {
		return nil, fmt.Errorf("解析虚拟机列表失败: %w", err)
	}
	return groups, nil
}

// ---------- 会话缓存 ----------

// Session 本地缓存的登录会话（含密码，仅本机 0600 权限保存，供自动校验）
type Session struct {
	Host     string    `json:"host"`
	User     string    `json:"user"`
	Token    string    `json:"csrf_token"`
	Cookie   string    `json:"login_cookie"`
	Password string    `json:"password,omitempty"`
	SavedAt  time.Time `json:"saved_at"`
}

// sessionFile 会话文件路径（可执行文件同目录）
func sessionFile() string {
	exe, err := os.Executable()
	if err != nil {
		return ".sangfor-session.json"
	}
	return filepath.Join(filepath.Dir(exe), ".sangfor-session.json")
}

func saveSession(s Session) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(sessionFile(), data, 0600)
}

func loadSession() (Session, error) {
	var s Session
	data, err := os.ReadFile(sessionFile())
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(data, &s)
	return s, err
}

func clearSession() {
	_ = os.Remove(sessionFile())
}

// ---------- 网口修改输入记忆 ----------

// LastInput 记录用户最后一次输入的网口配置（作为下次的默认值）
type LastInput struct {
	Host       string    `json:"host"`
	Iface      string    `json:"iface"`
	IP         string    `json:"ip"`
	Netmask    string    `json:"netmask"`
	Gateway    string    `json:"gateway"`
	MTU        string    `json:"mtu"`
	LinkMode   string    `json:"link_mode"`
	CustomName string    `json:"custom_name"`
	Desc       string    `json:"desc"`
	SavedAt    time.Time `json:"saved_at"`
}

// InputHistory 历史记录（最近使用的在前）
type InputHistory struct {
	Entries []LastInput `json:"entries"`
}

const maxHistory = 50

// historyFile 输入记忆文件路径（可执行文件同目录）
func historyFile() string {
	exe, err := os.Executable()
	if err != nil {
		return ".sangfor-lastinput.json"
	}
	return filepath.Join(filepath.Dir(exe), ".sangfor-lastinput.json")
}

func loadHistory() InputHistory {
	var h InputHistory
	data, err := os.ReadFile(historyFile())
	if err != nil {
		return h
	}
	_ = json.Unmarshal(data, &h)
	return h
}

// findLastInput 查找默认值: 严格匹配 同设备 + 同网口。
// 不做跨网口回退——否则可能把其它网口的 IP 误带到当前网口，造成 IP 冲突。
func findLastInput(host, iface string) (LastInput, bool) {
	h := loadHistory()
	for i := range h.Entries {
		e := h.Entries[i]
		if e.Host == host && strings.EqualFold(e.Iface, iface) {
			return e, true
		}
	}
	return LastInput{}, false
}

// saveLastInput 记录本次输入（同设备+同网口覆盖，最近使用置顶）
func saveLastInput(li LastInput) {
	h := loadHistory()
	out := []LastInput{li}
	for _, e := range h.Entries {
		if e.Host == li.Host && strings.EqualFold(e.Iface, li.Iface) {
			continue
		}
		out = append(out, e)
	}
	if len(out) > maxHistory {
		out = out[:maxHistory]
	}
	h.Entries = out
	if data, err := json.MarshalIndent(h, "", "  "); err == nil {
		_ = os.WriteFile(historyFile(), data, 0600)
	}
}

// ---------- 展示辅助 ----------

func ifaceStatus(s int) string {
	if s == 1 {
		return "UP"
	}
	return "DOWN"
}

func speedText(v, duplex int) string {
	if v <= 0 {
		return "-"
	}
	mode := "半双工"
	if duplex == 2 {
		mode = "全双工"
	}
	return fmt.Sprintf("%dMbps(%s)", v, mode)
}

func rolesText(r []string) string {
	if len(r) == 0 {
		return "-"
	}
	return strings.Join(r, ",")
}

// ---------- VXLAN / 管理网口 展示辅助 ----------

// hasRole 判断网口是否承担指定角色（role 数组，如 vxlan / mgmt / tercom）
func hasRole(f *Iface, r string) bool {
	for _, x := range f.Roles {
		if x == r {
			return true
		}
	}
	return false
}

// ifaceNodeText 网口所属节点（扁平接口用 node_name，分组结构用外层 node_name）
func ifaceNodeText(f Iface) string {
	if f.NodeName != "" {
		return f.NodeName
	}
	return orDash(f.NodeID)
}

// bondModeText bond/teaming 工作模式（非聚合口返回 "-"）
func bondModeText(f *Iface) string {
	if f.Type != "bond" && f.Mode == "" {
		return "-"
	}
	if f.Mode == "" {
		return "-"
	}
	return f.Mode
}

// membersText bond 成员口（如 eth2,eth3）
func membersText(f *Iface) string {
	if len(f.Members) == 0 {
		return "-"
	}
	return strings.Join(f.Members, ",")
}

// aliasIPText 别名 IP（如集群 IP，role=cluster_ip）
func aliasIPText(f *Iface) string {
	if len(f.Alias) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(f.Alias))
	for _, a := range f.Alias {
		if a.Role != "" {
			parts = append(parts, fmt.Sprintf("%s(%s)", a.IP, a.Role))
		} else {
			parts = append(parts, a.IP)
		}
	}
	return strings.Join(parts, " ")
}

// vxlanMTUText VXLAN 承载 MTU（非 VXLAN 口返回 "-"）
func vxlanMTUText(f *Iface) string {
	if f.VXLANMTU <= 0 {
		return "-"
	}
	return strconv.Itoa(f.VXLANMTU)
}

// vxlanAddrText VXLAN 承载地址信息（vxlan[] 内 ip/掩码/网关）
func vxlanAddrText(f *Iface) string {
	var parts []string
	for _, v := range f.VXLAN {
		if v.IP != "" {
			s := v.IP
			if v.Netmask != "" {
				s += "/" + v.Netmask
			}
			if v.Gateway != "" {
				s += " gw " + v.Gateway
			}
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, "; ")
}

// ifaceRemark 备注：优先 bdrSwitch，其次 desc
func ifaceRemark(f Iface) string {
	if f.BDRSwitch != "" {
		return f.BDRSwitch
	}
	return orDash(f.Desc)
}

// vxlanSummary VXLAN 网络页顶部统计
func vxlanSummary(vxlans, mgmts []Iface, errs []string) string {
	nodeSet := map[string]bool{}
	for _, f := range vxlans {
		nodeSet[f.NodeName] = true
	}
	for _, f := range mgmts {
		nodeSet[f.NodeName] = true
	}
	modeSet := map[string]bool{}
	for _, f := range vxlans {
		modeSet[f.IfaceMode] = true
	}
	modes := make([]string, 0, len(modeSet))
	for m := range modeSet {
		if m != "" {
			modes = append(modes, m)
		}
	}
	sort.Strings(modes)

	s := fmt.Sprintf("节点 %d 个 · VXLAN 网口 %d 个 · 管理网口 %d 个",
		len(nodeSet), len(vxlans), len(mgmts))
	if len(modes) > 0 {
		s += " · 承载模式 " + strings.Join(modes, "/")
	}
	if len(errs) > 0 {
		s += "  ⚠ " + strings.Join(errs, "; ")
	}
	return s
}

// vxlanReport 生成可复制的纯文本汇总（VXLAN 网口 + 管理网口）
func vxlanReport(vxlans, mgmts []Iface) string {
	var b strings.Builder
	b.WriteString("=== VXLAN 网口 ===\n")
	if len(vxlans) == 0 {
		b.WriteString("(无)\n")
	}
	for _, f := range vxlans {
		fmt.Fprintf(&b, "%s  %s  MAC=%s  模式=%s  物理MTU=%d  VXLAN MTU=%s  状态=%s  速率=%s  PCI=%s  角色=%s  承载地址=%s\n",
			ifaceNodeText(f), f.Name, orDash(f.MAC), orDash(f.IfaceMode), f.MTU,
			vxlanMTUText(&f), ifaceStatus(f.Status), speedText(f.Speed.Value, f.Speed.Duplex),
			orDash(f.PCIAddress), rolesText(f.Roles), vxlanAddrText(&f))
	}
	b.WriteString("\n=== 管理网口 ===\n")
	if len(mgmts) == 0 {
		b.WriteString("(无)\n")
	}
	for _, f := range mgmts {
		fmt.Fprintf(&b, "%s  %s  类型=%s  模式=%s  角色=%s  IP=%s/%s  网关=%s  别名=%s  成员=%s  状态=%s\n",
			ifaceNodeText(f), f.Name, orDash(f.Type), bondModeText(&f), rolesText(f.Roles),
			orDash(f.IP), orDash(f.Netmask), orDash(f.Gateway), aliasIPText(&f),
			membersText(&f), ifaceStatus(f.Status))
	}
	return b.String()
}

// gib 字节转 GiB/TiB 自适应字符串
func gib(b int64) string {
	g := float64(b) / 1024 / 1024 / 1024
	if g >= 1024 {
		return fmt.Sprintf("%.2fT", g/1024)
	}
	return fmt.Sprintf("%.1fG", g)
}

// uptimeText 秒转"X天X小时X分"
func uptimeText(sec int64) string {
	d := sec / 86400
	h := sec % 86400 / 3600
	m := sec % 3600 / 60
	switch {
	case d > 0:
		return fmt.Sprintf("%d天%d小时", d, h)
	case h > 0:
		return fmt.Sprintf("%d小时%d分", h, m)
	default:
		return fmt.Sprintf("%d分", m)
	}
}

// autoLinkMode 推导"自动协商"在该网卡上的取值。
// 关键点: 自动协商的序号并非固定（如 10G 网卡支持列表为 [12,5,6]），
// 因此优先按设备上报的状态推导: media=autonegotiation 时的 link_mode 即为该网卡的自动协商值；
// 否则退化为"支持列表中包含 6 则取 6"，仍不确定则返回 false 由用户选择。
func autoLinkMode(f *Iface) (int, bool) {
	if strings.EqualFold(f.Media, "autonegotiation") {
		for _, v := range f.SupportedModes {
			if v == f.LinkMode {
				return f.LinkMode, true
			}
		}
		return f.LinkMode, true
	}
	for _, v := range f.SupportedModes {
		if v == 6 {
			return 6, true
		}
	}
	return 0, false
}

// linkModeLabel 模式标签。auto 为该网卡的自动协商取值（未知则 -1）。
// 注意: 仅"自动协商"由设备状态确定，其余为常见速率/双工映射（1=10M 已实测印证），
// 未知取值显示为 模式N，提交时按用户输入的原值发送。
func linkModeLabel(m, auto int) string {
	if auto >= 0 && m == auto {
		return fmt.Sprintf("自动协商(%d)", m)
	}
	switch m {
	case 0:
		return "10M/半双工(0)"
	case 1:
		return "10M/全双工(1)"
	case 2:
		return "100M/半双工(2)"
	case 3:
		return "100M/全双工(3)"
	case 4:
		return "100M/全双工(4)"
	case 5:
		return "1000M/全双工(5)"
	case 12:
		return "10G/全双工(12)"
	default:
		return fmt.Sprintf("模式%d", m)
	}
}

// modesText 拼接可选的模式列表
func modesText(f *Iface) string {
	auto, ok := autoLinkMode(f)
	autoV := -1
	if ok {
		autoV = auto
	}
	parts := make([]string, 0, len(f.SupportedModes))
	for _, m := range f.SupportedModes {
		parts = append(parts, linkModeLabel(m, autoV))
	}
	return strings.Join(parts, "  ")
}

// ratioPct 设备返回的 0~1 小数比例转百分比字符串（如 "0.73" -> "73.0"）
func ratioPct(s string) string {
	if s == "" {
		return "-"
	}
	var f float64
	if _, err := fmt.Sscanf(s, "%g", &f); err != nil {
		return s
	}
	return fmt.Sprintf("%.1f", f*100)
}

// hostInfoText 将节点硬件信息格式化为区块化文本（GUI 硬件页展示）
func hostInfoText(info *HostInfo) string {
	var b strings.Builder
	put := func(format string, a ...interface{}) {
		fmt.Fprintf(&b, format, a...)
	}

	// 标题
	put("■ 节点: %s (%s)   状态: %s\n", info.Name, info.IP, info.Status)
	put("──────────────────────────────────────────\n")
	put("  序列号    : %s\n", orDash(info.SerialNumber))
	put("  机型      : %s (%s)\n", orDash(info.ServerModel), orDash(info.HardwareType))
	put("  系统版本  : %s\n", orDash(info.OSVersion))
	put("  开机时长  : %s\n", uptimeText(info.Uptime))
	put("  运行 VM   : %d 台\n", info.RunningVMs)

	// CPU
	cs := info.CPUStatus
	put("\n■ CPU\n")
	put("  型号      : %s\n", orDash(cs.CPUModel))
	put("  规格      : %d路 %d核 %d线程  %s MHz\n", cs.Sockets, cs.Cores, cs.Threads, orDash(cs.Mhz))
	put("  缓存      : %s\n", orDash(cs.Cache))
	put("  使用率    : %s%%\n", ratioPct(cs.Ratio))
	if len(cs.Temps) > 0 {
		parts := make([]string, 0, len(cs.Temps))
		for _, t := range cs.Temps {
			parts = append(parts, fmt.Sprintf("%s=%d°C", t.Name, t.Value))
		}
		put("  温度      : %s\n", strings.Join(parts, "  "))
	}

	// 内存
	put("\n■ 内存\n")
	put("  总计      : %s\n", gib(info.MemStatus.Total))
	put("  空闲      : %s\n", gib(info.MemStatus.Free))
	put("  使用率    : %s%%\n", ratioPct(info.MemStatus.Ratio))
	ml := info.MemLayout.Compute
	if ml.ConfTotalByte > 0 {
		put("  虚拟化配置: 总额 %s (超分 %d%%)  预分配 %s  超用 %s  可超用 %s\n",
			gib(ml.ConfTotalByte), ml.ConfOverPercent, gib(ml.PreallocatedByte), gib(ml.OverusedByte), gib(ml.OverusableByte))
	}

	// vCPU 超分
	cc := info.ConfCPU
	if cc.ConfTotalVcore > 0 {
		put("\n■ vCPU 超分\n")
		put("  已配 vCore : %d / %d\n", cc.ConfUsedVcore, cc.ConfTotalVcore)
		put("  物理核     : %d  超分 %d%%  使用率 %s%%\n", cc.TotalCPUVcore, cc.CPUOverPercent, ratioPct(cc.ConfUsedRate))
	}

	// 存储
	if len(info.StorageStatus) > 0 {
		put("\n■ 存储\n")
		for _, st := range info.StorageStatus {
			put("  %-12s (%s): 总 %s  已用 %s  可用 %s  %s%%\n",
				st.Name, st.Type, gib(st.Total), gib(st.Used), gib(st.Free), ratioPct(st.Ratio))
		}
	}

	// RAID 卡
	if len(info.RaidCardStatus) > 0 {
		put("\n■ RAID 卡\n")
		for name, rc := range info.RaidCardStatus {
			put("  %s: %s [%s]  物理盘 %s\n", name, rc.ControllerModel, rc.ControllerStat, rc.PhysicalDevNum)
		}
	}

	// 网卡
	if nc := info.NetCardsStatus; nc.Num > 0 {
		put("\n■ 网卡\n")
		uniq := map[string]int{}
		order := []string{}
		for _, card := range nc.Array {
			if _, ok := uniq[card.Type]; !ok {
				order = append(order, card.Type)
			}
			uniq[card.Type]++
		}
		parts := make([]string, 0, len(order))
		for _, t := range order {
			parts = append(parts, fmt.Sprintf("%s x%d", t, uniq[t]))
		}
		put("  数量      : %d 个\n", nc.Num)
		put("  类型      : %s\n", strings.Join(parts, ", "))
	}

	// 风扇
	if len(info.Fan) > 0 {
		put("\n■ 风扇\n")
		for _, f := range info.Fan {
			put("  %-6s: %d rpm  [%s]\n", f.Name, f.Speed, f.Status)
		}
	}

	// 电源
	if len(info.Power) > 0 {
		put("\n■ 电源\n")
		for _, p := range info.Power {
			put("  %s (%s)\n", orDash(p.ModelName), orDash(p.Vendor))
		}
	}
	put("\n")
	return b.String()
}

// changeItem 单条网口配置变更
type changeItem struct {
	field string // 字段名（中文，按显示宽度对齐）
	oldV  string // 当前值
	newV  string // 目标值
}

// buildChanges 对比当前网口与目标配置，返回结构化变更明细（空表示无变更）
func buildChanges(target *Iface, cfg IfaceConfig) []changeItem {
	curLink := fmt.Sprintf("%d", target.LinkMode)
	curLinkLabel := fmt.Sprintf("模式%d", target.LinkMode)
	if autoVal, ok := autoLinkMode(target); ok {
		curLinkLabel = linkModeLabel(target.LinkMode, autoVal)
	}
	curMTU := fmt.Sprintf("%d", target.MTU)

	items := []changeItem{}
	if cfg.IP != target.IP {
		items = append(items, changeItem{"IP", orDash(target.IP), orDash(cfg.IP)})
	}
	if cfg.Netmask != target.Netmask {
		items = append(items, changeItem{"掩码", orDash(target.Netmask), orDash(cfg.Netmask)})
	}
	if cfg.Gateway != target.Gateway {
		items = append(items, changeItem{"网关", orDash(target.Gateway), orDash(cfg.Gateway)})
	}
	if cfg.MTU != curMTU {
		items = append(items, changeItem{"MTU", curMTU, orDash(cfg.MTU)})
	}
	if cfg.LinkMode != curLink {
		newLabel := fmt.Sprintf("模式%s", cfg.LinkMode)
		if v, err := strconv.Atoi(cfg.LinkMode); err == nil {
			autoVal := -1
			if av, ok := autoLinkMode(target); ok {
				autoVal = av
			}
			newLabel = linkModeLabel(v, autoVal)
		}
		items = append(items, changeItem{"链路模式", curLinkLabel, newLabel})
	}
	if cfg.CustomName != target.CustomName {
		items = append(items, changeItem{"自定义名", orDash(target.CustomName), orDash(cfg.CustomName)})
	}
	if cfg.Desc != target.Desc {
		items = append(items, changeItem{"备注", orDash(target.Desc), orDash(cfg.Desc)})
	}
	return items
}

// dispWidth 字符串显示宽度（中文/全角按 2 计，用于等宽字体对齐）
func dispWidth(s string) int {
	w := 0
	for _, r := range s {
		if r > 0x2E7F {
			w += 2
		} else {
			w++
		}
	}
	return w
}

// padDisp 按显示宽度右补齐空格到 n
func padDisp(s string, n int) string {
	for dispWidth(s) < n {
		s += " "
	}
	return s
}

// formatChanges 将变更明细渲染为对齐表格文本（等宽字体下可读性最佳）
func formatChanges(items []changeItem) string {
	if len(items) == 0 {
		return ""
	}
	const (
		wIdx  = 4  // 序号列
		wMinF = 8  // 字段列最小宽度
		wMinV = 22 // 值列最小宽度
	)
	// 计算各列实际宽度（按显示宽度）
	wField, wOld, wNew := wMinF, wMinV, wMinV
	for _, it := range items {
		if d := dispWidth(it.field); d > wField {
			wField = d
		}
		if d := dispWidth(it.oldV); d > wOld {
			wOld = d
		}
		if d := dispWidth(it.newV); d > wNew {
			wNew = d
		}
	}

	var b strings.Builder
	sep := strings.Repeat("─", wIdx+wField+wOld+wNew+8)
	line := func(idx, f, ov, nv string) {
		b.WriteString("  " + padDisp(idx, wIdx) + " " +
			padDisp(f, wField) + " " +
			padDisp(ov, wOld) + " " +
			padDisp(nv, wNew) + "\n")
	}

	b.WriteString("  " + sep + "\n")
	line("#", "字段", "当前值", "新值")
	b.WriteString("  " + sep + "\n")
	for i, it := range items {
		line(fmt.Sprintf("%d", i+1), it.field, it.oldV, it.newV)
	}
	b.WriteString("  " + sep + "\n")
	b.WriteString(fmt.Sprintf("  共 %d 项变更\n", len(items)))
	return b.String()
}

// ---------- 工具函数 ----------

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func truncate(s string, n int) string {
	// 按「字符（rune）」计数而非字节，避免截断多字节中文时切到半个字符导致乱码/非法 UTF-8
	if r := []rune(s); len(r) <= n {
		return s
	} else {
		return string(r[:n]) + "..."
	}
}

// isAuthError 判断是否为鉴权失效（401）
func isAuthError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "HTTP 401")
}

// =====================================================================
//  桌面 GUI（Walk / Win32）
// =====================================================================

// 自定义消息：后台 goroutine 完成后通知 UI 线程
const (
	msgUIEvent = win.WM_APP + 100
)

// ---------- 后台任务 → UI 线程调度 ----------
//
// walk 没有官方提供的"后台线程调度到 UI 线程"API（控件不是线程安全的，
// 必须在创建它的线程更新）。这里通过子类化主窗口的窗口过程
// （SetWindowLongPtr GWL_WNDPROC）来接收自定义消息，从而在 UI 线程
// 消费 eventCh 中的事件。回调指针必须保存为包级变量防止被 GC 回收。

var (
	theApp     *App
	oldWndProc uintptr
	wndProcCb  uintptr
)

// uiWndProc 替换后的窗口过程：处理自定义消息，其余转发给原窗口过程
func uiWndProc(hwnd win.HWND, msg uint32, wParam, lParam uintptr) uintptr {
	if msg == msgUIEvent && theApp != nil {
		select {
		case ev := <-theApp.eventCh:
			theApp.handleEvent(ev)
		default:
		}
		return 0
	}
	return win.CallWindowProc(oldWndProc, hwnd, msg, wParam, lParam)
}

// installSubclass 替换主窗口的窗口过程
func (a *App) installSubclass() error {
	wndProcCb = syscall.NewCallback(uiWndProc)
	oldWndProc = win.SetWindowLongPtr(a.Handle(), win.GWL_WNDPROC, wndProcCb)
	if oldWndProc == 0 {
		return errors.New("SetWindowLongPtr 失败，无法接收后台消息")
	}
	return nil
}

// uiEvent 后台任务完成后投递给 UI 线程的事件
type uiEvent struct {
	kind string // login_ok / login_err / nodes_done / ifaces_done / vms_done / hw_done /
	//        vxlan_done / setiface_ifaces_done / setiface_task_done / setiface_reload_done / err
	err  error
	data interface{}
}

// ifaceRow 网口表格的一行（含所属节点）
type ifaceRow struct {
	node  string
	iface Iface
}

// vxlanData VXLAN 网络页一次刷新的结果（VXLAN 网口 + 管理网口 + 局部错误）
type vxlanData struct {
	vxlans []Iface
	mgmts  []Iface
	errs   []string
}

// ---------- 表格模型 ----------

type nodeModel struct {
	walk.TableModelBase
	items []ClusterNode
}

func (m *nodeModel) RowCount() int { return len(m.items) }

func (m *nodeModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(m.items) {
		return ""
	}
	n := m.items[row]
	switch col {
	case 0:
		return n.Node
	case 1:
		return n.Hostid
	case 2:
		return orDash(n.IP)
	case 3:
		return n.Status
	case 4:
		if n.Master == 1 {
			return "是"
		}
		return ""
	}
	return ""
}

type ifaceModel struct {
	walk.TableModelBase
	items []ifaceRow
}

func (m *ifaceModel) RowCount() int { return len(m.items) }

func (m *ifaceModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(m.items) {
		return ""
	}
	r := m.items[row]
	f := r.iface
	switch col {
	case 0:
		return r.node
	case 1:
		name := f.Name
		if f.CustomName != "" {
			name = f.Name + "(" + f.CustomName + ")"
		}
		return name
	case 2:
		return f.MAC
	case 3:
		return orDash(f.IP)
	case 4:
		return orDash(f.Netmask)
	case 5:
		return orDash(f.Gateway)
	case 6:
		return ifaceStatus(f.Status)
	case 7:
		return speedText(f.Speed.Value, f.Speed.Duplex)
	case 8:
		return f.IfaceMode
	case 9:
		return vxlanMTUText(&f) // 仅 VXLAN 承载口有值，其余显示 "-"
	case 10:
		return rolesText(f.Roles)
	case 11:
		return ifaceRemark(f)
	}
	return ""
}

// ---------- 通用网口列表表格（VXLAN 网口 / 管理网口 共用） ----------

// ifaceCol 一列的定义：标题、宽度、取值函数
type ifaceCol struct {
	title string
	width int
	value func(f Iface) string
}

// ifaceListModel 一层网口列表的表格模型，列由 ifaceCol 描述
type ifaceListModel struct {
	walk.TableModelBase
	cols  []ifaceCol
	items []Iface
}

func (m *ifaceListModel) RowCount() int { return len(m.items) }

func (m *ifaceListModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(m.items) || col < 0 || col >= len(m.cols) {
		return ""
	}
	return m.cols[col].value(m.items[row])
}

// newIfaceListModel 建模型并按其列定义装配 TableView 表头
func newIfaceListModel(tv *walk.TableView, cols []ifaceCol) *ifaceListModel {
	m := &ifaceListModel{cols: cols}
	tv.SetModel(m)
	for _, c := range cols {
		addCol(tv, c.title, c.width)
	}
	tv.SetColumnsOrderable(true)
	tv.SetLastColumnStretched(true)
	return m
}

// vxlanCols VXLAN 网口表列定义
func vxlanCols() []ifaceCol {
	return []ifaceCol{
		{"节点", 120, func(f Iface) string { return ifaceNodeText(f) }},
		{"网口", 90, func(f Iface) string {
			if f.CustomName != "" {
				return f.Name + "(" + f.CustomName + ")"
			}
			return f.Name
		}},
		{"MAC", 140, func(f Iface) string { return orDash(f.MAC) }},
		{"承载模式", 90, func(f Iface) string { return orDash(f.IfaceMode) }},
		{"物理MTU", 80, func(f Iface) string { return strconv.Itoa(f.MTU) }},
		{"VXLAN MTU", 90, func(f Iface) string { return vxlanMTUText(&f) }},
		{"状态", 60, func(f Iface) string { return ifaceStatus(f.Status) }},
		{"速率", 110, func(f Iface) string { return speedText(f.Speed.Value, f.Speed.Duplex) }},
		{"角色", 90, func(f Iface) string { return rolesText(f.Roles) }},
		{"承载地址", 130, func(f Iface) string { return vxlanAddrText(&f) }},
		{"PCI", 120, func(f Iface) string { return orDash(f.PCIAddress) }},
		{"驱动", 70, func(f Iface) string { return orDash(f.DriverType) }},
		{"备注", 120, func(f Iface) string { return ifaceRemark(f) }},
	}
}

// mgmtCols 管理网口表列定义
func mgmtCols() []ifaceCol {
	return []ifaceCol{
		{"节点", 120, func(f Iface) string { return ifaceNodeText(f) }},
		{"网口", 90, func(f Iface) string {
			if f.CustomName != "" {
				return f.Name + "(" + f.CustomName + ")"
			}
			return f.Name
		}},
		{"类型", 60, func(f Iface) string { return orDash(f.Type) }},
		{"聚合模式", 110, func(f Iface) string { return bondModeText(&f) }},
		{"角色", 120, func(f Iface) string { return rolesText(f.Roles) }},
		{"IP", 130, func(f Iface) string { return orDash(f.IP) }},
		{"掩码", 130, func(f Iface) string { return orDash(f.Netmask) }},
		{"网关", 130, func(f Iface) string { return orDash(f.Gateway) }},
		{"别名IP", 160, func(f Iface) string { return aliasIPText(&f) }},
		{"成员", 100, func(f Iface) string { return membersText(&f) }},
		{"状态", 60, func(f Iface) string { return ifaceStatus(f.Status) }},
		{"速率", 110, func(f Iface) string { return speedText(f.Speed.Value, f.Speed.Duplex) }},
		{"备注", 120, func(f Iface) string { return ifaceRemark(f) }},
	}
}

type vmModel struct {
	walk.TableModelBase
	items []vmRow
}

type vmRow struct {
	group string
	vm    VM
}

func (m *vmModel) RowCount() int { return len(m.items) }

func (m *vmModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(m.items) {
		return ""
	}
	r := m.items[row]
	v := r.vm
	switch col {
	case 0:
		return r.group
	case 1:
		return truncate(v.Name, 22)
	case 2:
		return v.VMID
	case 3:
		return v.Status
	case 4:
		return v.CPUs
	case 5:
		return gib(v.MemTotal)
	case 6:
		return gib(v.MemUsed)
	case 7:
		return gib(v.DiskUsed)
	case 8:
		return orDash(v.OSDistribution)
	case 9:
		return strings.Trim(v.HostConfig, "<>")
	}
	return ""
}

// ---------- 主窗口 ----------

type App struct {
	*walk.MainWindow
	eventCh chan uiEvent

	client *Client
	host   string
	user   string
	pass   string

	// 顶部登录栏
	hostEdit, userEdit, passEdit *walk.LineEdit
	loginBtn                     *walk.PushButton
	statusLabel                  *walk.Label

	// 功能页
	notebook *walk.TabWidget

	nodeTable *walk.TableView
	nodeModel *nodeModel
	nodes     []ClusterNode

	ifaceTable *walk.TableView
	ifaceModel *ifaceModel

	vmTable *walk.TableView
	vmModel *vmModel
	vmStat  *walk.Label

	hwScroll *walk.ScrollView

	// VXLAN 网络页
	vxlanTable *walk.TableView
	vxlanModel *ifaceListModel
	mgmtTable  *walk.TableView
	mgmtModel  *ifaceListModel
	vxlanStat  *walk.Label
	vxlanData  vxlanData // 最近一次拉取结果（供"复制"按钮使用）

	// 修改网口页
	nodeCombo, ifaceCombo, linkCombo                      *walk.ComboBox
	ipEdit, maskEdit, gwEdit, mtuEdit, nameEdit, descEdit *walk.LineEdit
	curInfoLabel                                          *walk.Label
	modesLabel                                            *walk.Label
	hintLabel                                             *walk.Label
	diffText                                              *walk.TextEdit
	previewBtn                                            *walk.PushButton
	submitBtn                                             *walk.PushButton

	selNode   *ClusterNode
	selIfaces []Iface
	selIface  *Iface
	linkVals  []int
}

// post 后台 goroutine 完成后通知 UI 线程
func (a *App) post(kind string, err error, data interface{}) {
	a.eventCh <- uiEvent{kind: kind, err: err, data: data}
	win.PostMessage(a.Handle(), msgUIEvent, 0, 0)
}

// setStatus 更新顶部状态栏
func (a *App) setStatus(s string) {
	a.statusLabel.SetText(s)
}

// handleEvent 在 UI 线程处理后台任务结果
func (a *App) handleEvent(ev uiEvent) {
	switch ev.kind {
	case "login_ok":
		role := ""
		if a.client != nil {
			role = a.client.role
		}
		a.setStatus(fmt.Sprintf("登录成功: %s (%s)", a.user, role))
		a.loginBtn.SetEnabled(true)
		a.loginBtn.SetText("重新登录")
		a.notebook.SetEnabled(true)
		a.fillNodeCombo()
		a.refreshAll()
	case "login_err":
		a.loginBtn.SetEnabled(true)
		a.setStatus("登录失败")
		walk.MsgBox(a, "登录失败", ev.err.Error(), walk.MsgBoxIconError)
	case "err":
		a.setStatus("操作失败: " + shortErr(ev.err))
		walk.MsgBox(a, "操作失败", ev.err.Error(), walk.MsgBoxIconError)
	case "nodes_done":
		a.nodes = ev.data.([]ClusterNode)
		a.nodeModel.items = a.nodes
		a.nodeModel.PublishRowsReset()
		a.fillNodeCombo()
		a.setStatus(fmt.Sprintf("节点 %d 个", len(a.nodes)))
	case "ifaces_done":
		rows := ev.data.([]ifaceRow)
		a.ifaceModel.items = rows
		a.ifaceModel.PublishRowsReset()
	case "vms_done":
		groups := ev.data.([]VMGroup)
		a.vmModel.items = flattenVMs(groups)
		a.vmModel.PublishRowsReset()
		total, running := 0, 0
		for _, g := range groups {
			total += len(g.Data)
			for _, v := range g.Data {
				if v.RunningStatus() {
					running++
				}
			}
		}
		a.vmStat.SetText(fmt.Sprintf("合计: %d 台虚拟机, %d 台运行中", total, running))
	case "hw_done":
		a.renderHW(ev.data.([]hwNodeInfo))
		a.setStatus("硬件信息已刷新")
	case "vxlan_done":
		d := ev.data.(vxlanData)
		a.vxlanData = d
		a.vxlanModel.items = d.vxlans
		a.vxlanModel.PublishRowsReset()
		a.mgmtModel.items = d.mgmts
		a.mgmtModel.PublishRowsReset()
		a.vxlanStat.SetText(vxlanSummary(d.vxlans, d.mgmts, d.errs))
		if len(d.errs) > 0 {
			a.setStatus("VXLAN 网络部分接口拉取失败")
		} else {
			a.setStatus(fmt.Sprintf("VXLAN 网络已刷新: %d 个 VXLAN 网口, %d 个管理网口",
				len(d.vxlans), len(d.mgmts)))
		}
	case "setiface_ifaces_done":
		ni := ev.data.(*NodeIfaces)
		a.selIfaces = ni.Data
		a.rebuildIfaceCombo()
	case "setiface_reload_done":
		// 提交后回读：更新当前节点网口数据并重选原网口
		ni := ev.data.(*NodeIfaces)
		a.selIfaces = ni.Data
		a.rebuildIfaceCombo()
		a.restoreIfaceSelection()
	case "setiface_task_done":
		canEdit := a.selIface != nil
		a.submitBtn.SetEnabled(canEdit)
		a.previewBtn.SetEnabled(canEdit)
		a.submitBtn.SetText("提交修改")
		msg := ev.data.(string)
		a.diffText.AppendText("\n[执行结果] " + orDash(msg) + "\n")
		if ev.err == nil {
			a.setStatus("网口修改任务执行完成")
			walk.MsgBox(a, "执行完成", "任务执行结果: "+orDash(msg), walk.MsgBoxIconInformation)
			// 回读确认
			if a.selNode != nil {
				go a.fetchIfacesForNode(a.selNode.Hostid, "setiface_reload_done")
			}
			a.refreshIfaces()
		} else {
			a.setStatus("任务执行失败")
			walk.MsgBox(a, "任务失败", ev.err.Error(), walk.MsgBoxIconError)
		}
	}
}

// flattenVMs 把分组列表拍平成表格行
func flattenVMs(groups []VMGroup) []vmRow {
	var rows []vmRow
	for _, g := range groups {
		for _, v := range g.Data {
			rows = append(rows, vmRow{group: g.Name, vm: v})
		}
	}
	return rows
}

// ---------- 硬件信息（结构化展示） ----------

// hwNodeInfo 单个节点的硬件信息（含获取错误）
type hwNodeInfo struct {
	node ClusterNode
	info *HostInfo
	err  error
}

// hwRow 硬件页键值行
func hwRow(parent walk.Container, key, val string) {
	row, _ := walk.NewComposite(parent)
	_ = row.SetLayout(walk.NewHBoxLayout())
	k, _ := walk.NewLabel(row)
	k.SetText(key)
	k.SetMinMaxSize(walk.Size{Width: 150, Height: 0}, walk.Size{Width: 150, Height: 0})
	v, _ := walk.NewLabel(row)
	v.SetText(val)
}

// hwSection 硬件页小节标题（加粗）
func hwSection(parent walk.Container, title string) {
	l, _ := walk.NewLabel(parent)
	l.SetText(title)
	f, _ := walk.NewFont("Microsoft YaHei", 9, walk.FontBold)
	l.SetFont(f)
}

// buildNodeBox 构建单个节点的硬件信息分组
func buildNodeBox(parent walk.Container, it hwNodeInfo) {
	gb, _ := walk.NewGroupBox(parent)
	_ = gb.SetLayout(walk.NewVBoxLayout())

	if it.err != nil {
		_ = gb.SetTitle(fmt.Sprintf("节点 %s (%s) - 获取失败", it.node.Node, it.node.Hostid))
		hwRow(gb, "错误", shortErr(it.err))
		return
	}
	info := it.info
	_ = gb.SetTitle(fmt.Sprintf("节点: %s (%s)   状态: %s", info.Name, info.IP, info.Status))

	// 顶部操作行：复制本节点信息到剪贴板
	opBar, _ := walk.NewComposite(gb)
	_ = opBar.SetLayout(walk.NewHBoxLayout())
	_, _ = walk.NewHSpacer(opBar)
	copyBtn, _ := walk.NewPushButton(opBar)
	copyBtn.SetText("复制本节点信息")
	copyBtn.Clicked().Attach(func() {
		text := hostInfoText(it.info)
		if err := walk.Clipboard().SetText(text); err != nil {
			walk.MsgBox(nil, "复制失败", "复制到剪贴板失败: "+err.Error(), walk.MsgBoxIconError)
			return
		}
		walk.MsgBox(nil, "已复制", "节点 "+it.info.Name+" 的硬件信息已复制到剪贴板。", walk.MsgBoxIconInformation)
	})

	// 基本信息
	hwRow(gb, "序列号", orDash(info.SerialNumber))
	hwRow(gb, "机型", fmt.Sprintf("%s (%s)", orDash(info.ServerModel), orDash(info.HardwareType)))
	hwRow(gb, "系统版本", orDash(info.OSVersion))
	hwRow(gb, "开机时长", uptimeText(info.Uptime))
	hwRow(gb, "运行 VM", fmt.Sprintf("%d 台", info.RunningVMs))

	// CPU
	cs := info.CPUStatus
	hwSection(gb, "CPU")
	hwRow(gb, "型号", orDash(cs.CPUModel))
	hwRow(gb, "规格", fmt.Sprintf("%d路 %d核 %d线程  %s MHz", cs.Sockets, cs.Cores, cs.Threads, orDash(cs.Mhz)))
	hwRow(gb, "缓存", orDash(cs.Cache))
	hwRow(gb, "使用率", ratioPct(cs.Ratio)+"%")
	if len(cs.Temps) > 0 {
		parts := make([]string, 0, len(cs.Temps))
		for _, t := range cs.Temps {
			parts = append(parts, fmt.Sprintf("%s=%d°C", t.Name, t.Value))
		}
		hwRow(gb, "温度", strings.Join(parts, "    "))
	}

	// 内存
	hwSection(gb, "内存")
	hwRow(gb, "总计", gib(info.MemStatus.Total))
	hwRow(gb, "空闲", gib(info.MemStatus.Free))
	hwRow(gb, "使用率", ratioPct(info.MemStatus.Ratio)+"%")
	ml := info.MemLayout.Compute
	if ml.ConfTotalByte > 0 {
		hwRow(gb, "虚拟化配置",
			fmt.Sprintf("总额 %s (超分 %d%%)  预分配 %s  超用 %s  可超用 %s",
				gib(ml.ConfTotalByte), ml.ConfOverPercent, gib(ml.PreallocatedByte), gib(ml.OverusedByte), gib(ml.OverusableByte)))
	}

	// vCPU 超分
	cc := info.ConfCPU
	if cc.ConfTotalVcore > 0 {
		hwSection(gb, "vCPU 超分")
		hwRow(gb, "已配 vCore", fmt.Sprintf("%d / %d", cc.ConfUsedVcore, cc.ConfTotalVcore))
		hwRow(gb, "物理核/超分", fmt.Sprintf("%d 核, 超分 %d%%, 使用率 %s%%",
			cc.TotalCPUVcore, cc.CPUOverPercent, ratioPct(cc.ConfUsedRate)))
	}

	// 存储
	if len(info.StorageStatus) > 0 {
		hwSection(gb, "存储")
		for _, st := range info.StorageStatus {
			hwRow(gb, st.Name+" ("+st.Type+")",
				fmt.Sprintf("总 %s  已用 %s  可用 %s  %s%%",
					gib(st.Total), gib(st.Used), gib(st.Free), ratioPct(st.Ratio)))
		}
	}

	// RAID 卡
	if len(info.RaidCardStatus) > 0 {
		hwSection(gb, "RAID 卡")
		for name, rc := range info.RaidCardStatus {
			hwRow(gb, name, fmt.Sprintf("%s [%s]  物理盘 %s", rc.ControllerModel, rc.ControllerStat, rc.PhysicalDevNum))
		}
	}

	// 网卡
	if nc := info.NetCardsStatus; nc.Num > 0 {
		hwSection(gb, "网卡")
		uniq := map[string]int{}
		order := []string{}
		for _, card := range nc.Array {
			if _, ok := uniq[card.Type]; !ok {
				order = append(order, card.Type)
			}
			uniq[card.Type]++
		}
		parts := make([]string, 0, len(order))
		for _, t := range order {
			parts = append(parts, fmt.Sprintf("%s x%d", t, uniq[t]))
		}
		hwRow(gb, "数量", fmt.Sprintf("%d 个", nc.Num))
		hwRow(gb, "类型", strings.Join(parts, ", "))
	}

	// 风扇
	if len(info.Fan) > 0 {
		hwSection(gb, "风扇")
		for _, f := range info.Fan {
			hwRow(gb, f.Name, fmt.Sprintf("%d rpm  [%s]", f.Speed, f.Status))
		}
	}

	// 电源
	if len(info.Power) > 0 {
		hwSection(gb, "电源")
		for _, p := range info.Power {
			hwRow(gb, orDash(p.ModelName), orDash(p.Vendor))
		}
	}
}

// disposeWidgetTree 递归销毁控件及其所有子控件。
// 注意：walk 的 WidgetList.Clear() 只把控件从布局列表移除，并不会销毁 Win32 窗口句柄，
// 也不会递归销毁子控件；若刷新时不显式销毁，旧窗口会残留在屏幕上叠加成"多个窗口"。
func disposeWidgetTree(w walk.Widget) {
	if c, ok := w.(walk.Container); ok {
		ch := c.Children()
		for i := ch.Len() - 1; i >= 0; i-- {
			if child := ch.At(i); child != nil {
				disposeWidgetTree(child)
			}
		}
	}
	w.Dispose()
}

// renderHW 重建硬件信息页（每个节点一个分组框，直接放在 ScrollView 上）
func (a *App) renderHW(list []hwNodeInfo) {
	// 先显式递归销毁旧控件，再清空布局列表
	ch := a.hwScroll.Children()
	for i := ch.Len() - 1; i >= 0; i-- {
		if w := ch.At(i); w != nil {
			disposeWidgetTree(w)
		}
	}
	_ = ch.Clear()

	if len(list) == 0 {
		l, _ := walk.NewLabel(a.hwScroll)
		l.SetText("未获取到节点硬件信息")
		a.hwScroll.RequestLayout()
		return
	}
	for _, it := range list {
		buildNodeBox(a.hwScroll, it)
	}
	a.hwScroll.RequestLayout()
}

// ---------- 后台任务 ----------

func (a *App) fetchNodes() {
	c := a.client
	nodes, err := c.GetNodeList()
	if err != nil {
		a.post("err", fmt.Errorf("获取节点列表失败: %w", err), nil)
		return
	}
	a.post("nodes_done", nil, nodes)
}

func (a *App) fetchIfacesAll() {
	c := a.client

	// 快路径：不带 node_id 的 /cluster/network/ifaces 一次返回全集群网口（实测可行），
	// 由 4 节点 × 2 次请求 = 8 次降到 1 次。
	if groups, err := c.GetAllIfaces(); err == nil && len(groups) > 0 {
		var rows []ifaceRow
		for _, g := range groups {
			for _, f := range g.Data {
				rows = append(rows, ifaceRow{node: g.NodeName, iface: f})
			}
		}
		if len(rows) > 0 {
			a.post("ifaces_done", nil, rows)
			return
		}
	}

	// 慢路径（兼容旧固件/接口行为变化）：先拉节点列表，再逐节点拉网口
	nodes, err := c.GetNodeList()
	if err != nil {
		a.post("err", fmt.Errorf("获取节点列表失败: %w", err), nil)
		return
	}
	var rows []ifaceRow
	for _, n := range nodes {
		if !strings.HasPrefix(n.Hostid, "host-") {
			continue
		}
		ni, err := c.GetIfaces(n.Hostid)
		if err != nil {
			continue
		}
		for _, f := range ni.Data {
			rows = append(rows, ifaceRow{node: n.Node, iface: f})
		}
	}
	a.post("ifaces_done", nil, rows)
}

// fetchVXLAN 拉取 VXLAN 网口 + 管理网口（两个接口各自容错，互不阻塞）
func (a *App) fetchVXLAN() {
	c := a.client
	var d vxlanData
	if vx, err := c.GetVXLANIfaces(); err != nil {
		d.errs = append(d.errs, "VXLAN 网口: "+shortErr(err))
	} else {
		d.vxlans = vx
	}
	if mg, err := c.GetMgmtIfaces(); err != nil {
		d.errs = append(d.errs, "管理网口: "+shortErr(err))
	} else {
		d.mgmts = mg
	}
	a.post("vxlan_done", nil, d)
}

func (a *App) fetchVMs() {
	c := a.client
	groups, err := c.GetVMList()
	if err != nil {
		a.post("err", fmt.Errorf("获取虚拟机列表失败: %w", err), nil)
		return
	}
	a.post("vms_done", nil, groups)
}

func (a *App) fetchHW() {
	c := a.client
	nodes, err := c.GetNodeList()
	if err != nil {
		a.post("err", fmt.Errorf("获取节点列表失败: %w", err), nil)
		return
	}
	var list []hwNodeInfo
	for _, n := range nodes {
		if !strings.HasPrefix(n.Hostid, "host-") {
			continue
		}
		info, err := c.GetHostInfo(n.Hostid)
		list = append(list, hwNodeInfo{node: n, info: info, err: err})
	}
	a.post("hw_done", nil, list)
}

// fetchIfacesForNode 拉取指定节点网口（修改网口页使用）
func (a *App) fetchIfacesForNode(nodeID, kind string) {
	c := a.client
	ni, err := c.GetIfaces(nodeID)
	if err != nil {
		a.post("err", fmt.Errorf("获取节点网口失败: %w", err), nil)
		return
	}
	a.post(kind, nil, ni)
}

// refreshAll 登录成功后刷新全部数据
func (a *App) refreshAll() {
	go a.fetchNodes()
	go a.fetchIfacesAll()
	go a.fetchVXLAN()
	go a.fetchVMs()
	go a.fetchHW()
}

// refreshIfaces 仅刷新网口表格
func (a *App) refreshIfaces() {
	go a.fetchIfacesAll()
}

// ---------- 修改网口页逻辑 ----------

// fillNodeCombo 填充修改网口页的节点下拉（仅 host-* 节点）
func (a *App) fillNodeCombo() {
	var labels []string
	for _, n := range a.nodes {
		if strings.HasPrefix(n.Hostid, "host-") {
			labels = append(labels, fmt.Sprintf("%s (%s)", n.Node, n.Hostid))
		}
	}
	_ = a.nodeCombo.SetModel(labels)
	if len(labels) > 0 {
		_ = a.nodeCombo.SetCurrentIndex(0)
	} else {
		a.nodeCombo.SetEnabled(false)
		a.ifaceCombo.SetEnabled(false)
		a.setStatus("未找到可操作的节点")
	}
}

// onNodeChanged 节点下拉变化 → 拉取该节点网口
func (a *App) onNodeChanged() {
	idx := a.nodeCombo.CurrentIndex()
	var hosts []ClusterNode
	for _, n := range a.nodes {
		if strings.HasPrefix(n.Hostid, "host-") {
			hosts = append(hosts, n)
		}
	}
	if idx < 0 || idx >= len(hosts) {
		return
	}
	a.selNode = &hosts[idx]
	a.ifaceCombo.SetEnabled(false)
	a.diffText.SetText("")
	go a.fetchIfacesForNode(a.selNode.Hostid, "setiface_ifaces_done")
}

// rebuildIfaceCombo 重建网口下拉
func (a *App) rebuildIfaceCombo() {
	var labels []string
	for _, f := range a.selIfaces {
		name := f.Name
		if f.CustomName != "" {
			name = f.Name + "(" + f.CustomName + ")"
		}
		labels = append(labels, fmt.Sprintf("%s  %s  %s", name, f.MAC, orDash(f.IP)))
	}
	_ = a.ifaceCombo.SetModel(labels)
	if len(labels) > 0 {
		a.ifaceCombo.SetEnabled(true)
		_ = a.ifaceCombo.SetCurrentIndex(0)
	} else {
		a.ifaceCombo.SetEnabled(false)
	}
}

// restoreIfaceSelection 提交回读后尽量恢复原网口选中
func (a *App) restoreIfaceSelection() {
	if a.selIface == nil {
		return
	}
	for i := range a.selIfaces {
		if a.selIfaces[i].Name == a.selIface.Name {
			_ = a.ifaceCombo.SetCurrentIndex(i)
			return
		}
	}
	if len(a.selIfaces) > 0 {
		_ = a.ifaceCombo.SetCurrentIndex(0)
	}
}

// onIfaceChanged 网口下拉变化 → 展示当前配置并填默认值
func (a *App) onIfaceChanged() {
	idx := a.ifaceCombo.CurrentIndex()
	if idx < 0 || idx >= len(a.selIfaces) {
		return
	}
	f := &a.selIfaces[idx]
	a.selIface = f

	// 当前配置概要（只读展示）
	label := ""
	if autoVal, ok := autoLinkMode(f); ok {
		label = linkModeLabel(f.LinkMode, autoVal)
	} else {
		label = fmt.Sprintf("模式%d", f.LinkMode)
	}
	a.curInfoLabel.SetText(fmt.Sprintf(
		"当前 [%s]: IP=%s  掩码=%s  网关=%s  MTU=%d  链路模式=%s",
		f.Name, orDash(f.IP), orDash(f.Netmask), orDash(f.Gateway), f.MTU, label))
	a.modesLabel.SetText("该网卡支持的链路模式: " + modesText(f))

	// 选中网口后全部字段开放编辑
	a.ipEdit.SetEnabled(true)
	a.maskEdit.SetEnabled(true)
	a.gwEdit.SetEnabled(true)
	a.mtuEdit.SetEnabled(true)
	a.nameEdit.SetEnabled(true)
	a.descEdit.SetEnabled(true)
	a.linkCombo.SetEnabled(true)
	a.previewBtn.SetEnabled(true)
	a.submitBtn.SetEnabled(true)
	a.diffText.SetText("")

	// 各字段默认值：优先上次输入，否则设备当前值
	last, hasLast := findLastInput(a.client.baseURL, f.Name)
	defIP, defMask := f.IP, f.Netmask
	defGW, defMTU := f.Gateway, fmt.Sprintf("%d", f.MTU)
	defName, defDesc := f.CustomName, f.Desc
	defLinkMode := f.LinkMode
	if hasLast {
		if last.IP != "" {
			defIP = last.IP
		}
		if last.Netmask != "" {
			defMask = last.Netmask
		}
		if last.Gateway != "" {
			defGW = last.Gateway
		}
		if last.MTU != "" {
			defMTU = last.MTU
		}
		if last.CustomName != "" {
			defName = last.CustomName
		}
		if last.Desc != "" {
			defDesc = last.Desc
		}
		if v, err := strconv.Atoi(last.LinkMode); err == nil {
			defLinkMode = v
		}
	}
	a.ipEdit.SetText(defIP)
	a.maskEdit.SetText(defMask)
	a.gwEdit.SetText(defGW)
	a.mtuEdit.SetText(defMTU)
	a.nameEdit.SetText(defName)
	a.descEdit.SetText(defDesc)

	// 链路模式下拉（可选，支持设备上报的模式 + 当前模式）
	a.linkVals = nil
	var linkLabels []string
	autoVal := -1
	if av, ok := autoLinkMode(f); ok {
		autoVal = av
	}
	curIdx := 0
	seen := map[int]bool{}
	add := func(m int) {
		if seen[m] {
			return
		}
		seen[m] = true
		a.linkVals = append(a.linkVals, m)
		linkLabels = append(linkLabels, linkModeLabel(m, autoVal))
	}
	for _, m := range f.SupportedModes {
		add(m)
	}
	if !seen[defLinkMode] {
		linkLabels = append(linkLabels, fmt.Sprintf("当前:模式%d", defLinkMode))
		a.linkVals = append(a.linkVals, defLinkMode)
	}
	_ = a.linkCombo.SetModel(linkLabels)
	for i, mv := range a.linkVals {
		if mv == defLinkMode {
			curIdx = i
			break
		}
	}
	_ = a.linkCombo.SetCurrentIndex(curIdx)
}

// currentCfg 组装目标配置（全部字段取自输入框/下拉，未选网口时返回空）
func (a *App) currentCfg() IfaceConfig {
	if a.selIface == nil {
		return IfaceConfig{}
	}
	linkMode := ""
	if idx := a.linkCombo.CurrentIndex(); idx >= 0 && idx < len(a.linkVals) {
		linkMode = fmt.Sprintf("%d", a.linkVals[idx])
	}
	return IfaceConfig{
		Desc:       a.descEdit.Text(),
		IP:         a.ipEdit.Text(),
		Netmask:    a.maskEdit.Text(),
		Gateway:    a.gwEdit.Text(),
		LinkMode:   linkMode,
		MTU:        a.mtuEdit.Text(),
		MAC:        a.selIface.MAC,
		CustomName: a.nameEdit.Text(),
	}
}

// onPreview 预览变更
func (a *App) onPreview() {
	if a.selIface == nil {
		walk.MsgBox(a, "提示", "请先选择网口", walk.MsgBoxIconInformation)
		return
	}
	cfg := a.currentCfg()
	items := buildChanges(a.selIface, cfg)
	if len(items) == 0 {
		a.diffText.SetText("未检测到任何变更。")
		return
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("目标: 节点 %s 网口 %s\n\n", a.selNode.Node, a.selIface.Name))
	b.WriteString(formatChanges(items))
	b.WriteString("\n⚠ 此操作非常危险，可能导致网络中断或不可逆的配置变更！")
	a.diffText.SetText(b.String())
}

// onSubmit 提交修改（跳过密码二次校验，直接提交）
func (a *App) onSubmit() {
	if a.selIface == nil {
		walk.MsgBox(a, "提示", "请先选择网口", walk.MsgBoxIconInformation)
		return
	}
	cfg := a.currentCfg()
	items := buildChanges(a.selIface, cfg)
	if len(items) == 0 {
		walk.MsgBox(a, "提示", "未检测到任何变更。", walk.MsgBoxIconInformation)
		return
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("即将对节点 %s 的网口 %s 应用以下变更:\n\n", a.selNode.Node, a.selIface.Name))
	b.WriteString(formatChanges(items))
	b.WriteString("\n⚠ 此操作非常危险，可能导致网络中断或不可逆的配置变更！\n")
	b.WriteString("确认执行请点击 [是]，点击 [否] 取消。")
	a.diffText.SetText(b.String())

	ret := walk.MsgBox(a, "危险操作确认", b.String(), walk.MsgBoxYesNo|walk.MsgBoxIconWarning)
	if ret != walk.DlgCmdYes {
		return
	}

	// 提交（GUI 版按需求跳过 VerifyPassword 密码二次校验，后续人工验证）
	a.submitBtn.SetEnabled(false)
	a.previewBtn.SetEnabled(false)
	a.submitBtn.SetText("执行中...")
	a.setStatus("正在提交网口修改任务...")
	nodeID, ifaceName := a.selNode.Hostid, a.selIface.Name
	client := a.client
	go func() {
		taskID, err := client.SetIface(nodeID, ifaceName, cfg)
		if err != nil {
			a.post("setiface_task_done", err, "")
			return
		}
		msg, err := client.WaitTask(taskID, 2*time.Minute)
		if err != nil {
			// 任务失败（含超时）不记录输入，避免把未生效/失败配置当成默认值代入下次
			a.post("setiface_task_done", err, msg)
			return
		}
		// 记录本次输入作为下次默认值（仅在任务成功时）
		saveLastInput(LastInput{
			Host: client.baseURL, Iface: ifaceName,
			IP: cfg.IP, Netmask: cfg.Netmask, Gateway: cfg.Gateway, MTU: cfg.MTU,
			LinkMode: cfg.LinkMode, CustomName: cfg.CustomName, Desc: cfg.Desc,
			SavedAt: time.Now(),
		})
		a.post("setiface_task_done", nil, msg)
	}()
}

// addCol 向表格添加一列
func addCol(tv *walk.TableView, title string, width int) {
	c := walk.NewTableViewColumn()
	c.SetTitle(title)
	c.SetWidth(width)
	_ = tv.Columns().Add(c)
}

// ---------- 界面搭建 ----------

func newApp() (*App, error) {
	a := &App{
		eventCh: make(chan uiEvent, 32),
	}

	mw, err := walk.NewMainWindow()
	if err != nil {
		return nil, err
	}
	a.MainWindow = mw
	if err := mw.SetTitle("深信服设备管理工具"); err != nil {
		return nil, err
	}
	if err := mw.SetLayout(walk.NewVBoxLayout()); err != nil {
		return nil, err
	}
	mw.SetSize(walk.Size{Width: 1080, Height: 720})
	mw.SetMinMaxSize(walk.Size{Width: 800, Height: 560}, walk.Size{Width: 0, Height: 0})

	// ---- 顶部登录栏 ----
	topBar, err := walk.NewComposite(mw)
	if err != nil {
		return nil, err
	}
	if err := topBar.SetLayout(walk.NewHBoxLayout()); err != nil {
		return nil, err
	}

	hostLbl, _ := walk.NewLabel(topBar)
	hostLbl.SetText("设备:")
	a.hostEdit, _ = walk.NewLineEdit(topBar)
	a.hostEdit.SetSize(walk.Size{Width: 160, Height: 24})

	userLbl, _ := walk.NewLabel(topBar)
	userLbl.SetText("账号:")
	a.userEdit, _ = walk.NewLineEdit(topBar)
	a.userEdit.SetSize(walk.Size{Width: 100, Height: 24})

	passLbl, _ := walk.NewLabel(topBar)
	passLbl.SetText("密码:")
	a.passEdit, _ = walk.NewLineEdit(topBar)
	a.passEdit.SetPasswordMode(true)
	a.passEdit.SetSize(walk.Size{Width: 100, Height: 24})

	a.loginBtn, _ = walk.NewPushButton(topBar)
	a.loginBtn.SetText("登录")
	a.loginBtn.Clicked().Attach(a.onLogin)

	a.statusLabel, _ = walk.NewLabel(topBar)
	a.statusLabel.SetText("未登录")
	// 限制状态文字宽度，避免把登录按钮挤出可视区
	a.statusLabel.SetMinMaxSize(walk.Size{Width: 40, Height: 0}, walk.Size{Width: 380, Height: 0})

	// ---- 功能页 ----
	a.notebook, err = walk.NewTabWidget(mw)
	if err != nil {
		return nil, err
	}
	a.notebook.SetEnabled(false)

	// 节点页
	nodePage, _ := walk.NewTabPage()
	nodePage.SetTitle("集群节点")
	nodePage.SetLayout(walk.NewVBoxLayout())
	{
		bar, _ := walk.NewComposite(nodePage)
		bar.SetLayout(walk.NewHBoxLayout())
		btn, _ := walk.NewPushButton(bar)
		btn.SetText("刷新")
		btn.Clicked().Attach(func() { go a.fetchNodes() })
		lbl, _ := walk.NewLabel(bar)
		lbl.SetText("节点列表")

		a.nodeTable, _ = walk.NewTableView(nodePage)
		a.nodeModel = &nodeModel{}
		a.nodeTable.SetModel(a.nodeModel)
		addCol(a.nodeTable, "节点", 160)
		addCol(a.nodeTable, "hostid", 180)
		addCol(a.nodeTable, "IP", 140)
		addCol(a.nodeTable, "状态", 80)
		addCol(a.nodeTable, "主节点", 70)
		a.nodeTable.SetColumnsOrderable(true)
		a.nodeTable.SetLastColumnStretched(true)
	}
	a.notebook.Pages().Add(nodePage)

	// 网口页
	ifacePage, _ := walk.NewTabPage()
	ifacePage.SetTitle("网口信息")
	ifacePage.SetLayout(walk.NewVBoxLayout())
	{
		bar, _ := walk.NewComposite(ifacePage)
		bar.SetLayout(walk.NewHBoxLayout())
		btn, _ := walk.NewPushButton(bar)
		btn.SetText("刷新")
		btn.Clicked().Attach(a.refreshIfaces)
		lbl, _ := walk.NewLabel(bar)
		lbl.SetText("所有节点网口")

		a.ifaceTable, _ = walk.NewTableView(ifacePage)
		a.ifaceModel = &ifaceModel{}
		a.ifaceTable.SetModel(a.ifaceModel)
		addCol(a.ifaceTable, "节点", 100)
		addCol(a.ifaceTable, "网口", 90)
		addCol(a.ifaceTable, "MAC", 150)
		addCol(a.ifaceTable, "IP", 120)
		addCol(a.ifaceTable, "掩码", 120)
		addCol(a.ifaceTable, "网关", 120)
		addCol(a.ifaceTable, "状态", 60)
		addCol(a.ifaceTable, "速率", 100)
		addCol(a.ifaceTable, "模式", 70)
		addCol(a.ifaceTable, "VXLAN MTU", 90)
		addCol(a.ifaceTable, "角色", 100)
		addCol(a.ifaceTable, "备注", 150)
		a.ifaceTable.SetColumnsOrderable(true)
		a.ifaceTable.SetLastColumnStretched(true)
	}
	a.notebook.Pages().Add(ifacePage)

	// VXLAN 网络页
	vxlanPage, _ := walk.NewTabPage()
	vxlanPage.SetTitle("VXLAN 网络")
	vxlanPage.SetLayout(walk.NewVBoxLayout())
	{
		bar, _ := walk.NewComposite(vxlanPage)
		bar.SetLayout(walk.NewHBoxLayout())
		btn, _ := walk.NewPushButton(bar)
		btn.SetText("刷新")
		btn.Clicked().Attach(func() { go a.fetchVXLAN() })
		copyBtn, _ := walk.NewPushButton(bar)
		copyBtn.SetText("复制汇总")
		copyBtn.Clicked().Attach(func() {
			d := a.vxlanData
			if len(d.vxlans) == 0 && len(d.mgmts) == 0 {
				walk.MsgBox(a, "无数据", "请先点击「刷新」拉取 VXLAN 网络信息。", walk.MsgBoxIconInformation)
				return
			}
			if err := walk.Clipboard().SetText(vxlanReport(d.vxlans, d.mgmts)); err != nil {
				walk.MsgBox(a, "复制失败", "复制到剪贴板失败: "+err.Error(), walk.MsgBoxIconError)
				return
			}
			walk.MsgBox(a, "已复制", "VXLAN 网络信息已复制到剪贴板。", walk.MsgBoxIconInformation)
		})
		a.vxlanStat, _ = walk.NewLabel(bar)
		a.vxlanStat.SetText("点击「刷新」加载 VXLAN 网口与管理网口")

		// 上下两块用 Splitter 分隔，可拖动分隔条调整比例
		sp, _ := walk.NewVSplitter(vxlanPage)
		sp.SetHandleWidth(6)

		gbV, _ := walk.NewGroupBox(sp)
		_ = gbV.SetTitle("VXLAN 网口（隧道承载口，来自 vxlan-ifaces）")
		_ = gbV.SetLayout(walk.NewVBoxLayout())
		a.vxlanTable, _ = walk.NewTableView(gbV)
		a.vxlanModel = newIfaceListModel(a.vxlanTable, vxlanCols())

		gbM, _ := walk.NewGroupBox(sp)
		_ = gbM.SetTitle("管理网口（mgmt / 集群 IP，来自 mgmt-ifaces）")
		_ = gbM.SetLayout(walk.NewVBoxLayout())
		a.mgmtTable, _ = walk.NewTableView(gbM)
		a.mgmtModel = newIfaceListModel(a.mgmtTable, mgmtCols())
	}
	a.notebook.Pages().Add(vxlanPage)

	// 虚拟机页
	vmPage, _ := walk.NewTabPage()
	vmPage.SetTitle("虚拟机列表")
	vmPage.SetLayout(walk.NewVBoxLayout())
	{
		bar, _ := walk.NewComposite(vmPage)
		bar.SetLayout(walk.NewHBoxLayout())
		btn, _ := walk.NewPushButton(bar)
		btn.SetText("刷新")
		btn.Clicked().Attach(func() { go a.fetchVMs() })
		a.vmStat, _ = walk.NewLabel(bar)
		a.vmStat.SetText("")

		a.vmTable, _ = walk.NewTableView(vmPage)
		a.vmModel = &vmModel{}
		a.vmTable.SetModel(a.vmModel)
		addCol(a.vmTable, "分组", 90)
		addCol(a.vmTable, "名称", 150)
		addCol(a.vmTable, "vmid", 70)
		addCol(a.vmTable, "状态", 80)
		addCol(a.vmTable, "vCPU", 50)
		addCol(a.vmTable, "内存", 80)
		addCol(a.vmTable, "内存占用", 80)
		addCol(a.vmTable, "磁盘", 80)
		addCol(a.vmTable, "操作系统", 160)
		addCol(a.vmTable, "主机", 120)
		a.vmTable.SetColumnsOrderable(true)
		a.vmTable.SetLastColumnStretched(true)
	}
	a.notebook.Pages().Add(vmPage)

	// 硬件页
	hwPage, _ := walk.NewTabPage()
	hwPage.SetTitle("硬件信息")
	hwPage.SetLayout(walk.NewVBoxLayout())
	{
		bar, _ := walk.NewComposite(hwPage)
		bar.SetLayout(walk.NewHBoxLayout())
		btn, _ := walk.NewPushButton(bar)
		btn.SetText("刷新")
		btn.Clicked().Attach(func() { go a.fetchHW() })
		lbl, _ := walk.NewLabel(bar)
		lbl.SetText("每个节点一个分组，可滚动查看")

		a.hwScroll, _ = walk.NewScrollView(hwPage)
		// ScrollView 的 Children()/SetLayout() 已代理到其内部 composite，
		// 直接把它当容器使用，不要再额外包一层
		_ = a.hwScroll.SetLayout(walk.NewVBoxLayout())
		hint, _ := walk.NewLabel(a.hwScroll)
		hint.SetText("点击上方「刷新」加载硬件信息")
	}
	a.notebook.Pages().Add(hwPage)

	// 修改网口页
	setPage, _ := walk.NewTabPage()
	setPage.SetTitle("修改网口配置")
	if err := setPage.SetLayout(walk.NewVBoxLayout()); err != nil {
		return nil, err
	}
	{
		selBar, _ := walk.NewComposite(setPage)
		selBar.SetLayout(walk.NewHBoxLayout())
		lblN, _ := walk.NewLabel(selBar)
		lblN.SetText("节点:")
		a.nodeCombo, _ = walk.NewComboBox(selBar)
		a.nodeCombo.SetSize(walk.Size{Width: 260, Height: 24})
		a.nodeCombo.CurrentIndexChanged().Attach(a.onNodeChanged)
		lblI, _ := walk.NewLabel(selBar)
		lblI.SetText("网口:")
		// 网口用 DropDownList 样式：不可编辑（防误删），点击输入框任意位置都会弹出下拉
		a.ifaceCombo, _ = walk.NewDropDownBox(selBar)
		a.ifaceCombo.SetSize(walk.Size{Width: 300, Height: 24})
		a.ifaceCombo.CurrentIndexChanged().Attach(a.onIfaceChanged)

		a.curInfoLabel, _ = walk.NewLabel(setPage)
		a.curInfoLabel.SetText("请选择节点和网口")
		a.modesLabel, _ = walk.NewLabel(setPage)
		a.modesLabel.SetText("")
		a.hintLabel, _ = walk.NewLabel(setPage)
		a.hintLabel.SetText("支持修改 IP/掩码/网关/MTU/自定义名称/备注/链路模式，提交前请仔细核对")

		form, _ := walk.NewComposite(setPage)
		// 注意：walk 的 GridLayout 需要显式 SetRange 才会排布控件（手动 API 下不会自动流式排布），
		// 因此表单改用 VBox + 每行一个 HBox（label 固定宽 + 输入框），这是可靠的布局方式。
		form.SetLayout(walk.NewVBoxLayout())
		mkRow := func(label string) *walk.Composite {
			row, _ := walk.NewComposite(form)
			_ = row.SetLayout(walk.NewHBoxLayout())
			lb, _ := walk.NewLabel(row)
			lb.SetText(label)
			lb.SetMinMaxSize(walk.Size{Width: 110, Height: 0}, walk.Size{Width: 110, Height: 0})
			return row
		}
		a.ipEdit, _ = walk.NewLineEdit(mkRow("IP:"))
		a.maskEdit, _ = walk.NewLineEdit(mkRow("掩码:"))
		a.gwEdit, _ = walk.NewLineEdit(mkRow("网关:"))
		a.mtuEdit, _ = walk.NewLineEdit(mkRow("MTU:"))
		a.nameEdit, _ = walk.NewLineEdit(mkRow("自定义名称:"))
		a.descEdit, _ = walk.NewLineEdit(mkRow("备注:"))
		// 链路模式用 DropDownList 样式：不可编辑（防误删），点击任意位置弹出下拉
		a.linkCombo, _ = walk.NewDropDownBox(mkRow("链路模式:"))
		// 初始未选网口时全部禁用，选中网口后由 onIfaceChanged 开放全部字段
		a.ipEdit.SetEnabled(false)
		a.maskEdit.SetEnabled(false)
		a.gwEdit.SetEnabled(false)
		a.mtuEdit.SetEnabled(false)
		a.nameEdit.SetEnabled(false)
		a.descEdit.SetEnabled(false)
		a.linkCombo.SetEnabled(false)

		btnBar, _ := walk.NewComposite(setPage)
		btnBar.SetLayout(walk.NewHBoxLayout())
		a.previewBtn, _ = walk.NewPushButton(btnBar)
		a.previewBtn.SetText("预览变更")
		a.previewBtn.Clicked().Attach(a.onPreview)
		a.submitBtn, _ = walk.NewPushButton(btnBar)
		a.submitBtn.SetText("提交修改")
		a.submitBtn.Clicked().Attach(a.onSubmit)
		a.previewBtn.SetEnabled(false)
		a.submitBtn.SetEnabled(false)
		hint, _ := walk.NewLabel(btnBar)
		hint.SetText("⚠ 修改网口为危险写操作，提交后可能导致网络中断")

		a.diffText, _ = walk.NewTextEdit(setPage)
		a.diffText.SetReadOnly(true)
		font, _ := walk.NewFont("Consolas", 9, 0)
		a.diffText.SetFont(font)
	}
	a.notebook.Pages().Add(setPage)

	// 菜单
	fileMenu, _ := walk.NewMenu()
	fileAction, _ := mw.Menu().Actions().AddMenu(fileMenu)
	fileAction.SetText("文件(&F)")
	refreshItem := walk.NewAction()
	refreshItem.SetText("刷新全部(&R)")
	refreshItem.Triggered().Attach(func() {
		if a.client != nil {
			a.refreshAll()
		}
	})
	fileMenu.Actions().Add(refreshItem)
	exitItem := walk.NewAction()
	exitItem.SetText("退出(&X)")
	exitItem.Triggered().Attach(func() { mw.Close() })
	fileMenu.Actions().Add(exitItem)

	opMenu, _ := walk.NewMenu()
	opAction, _ := mw.Menu().Actions().AddMenu(opMenu)
	opAction.SetText("操作(&O)")
	loginItem := walk.NewAction()
	loginItem.SetText("重新登录(&L)")
	loginItem.Triggered().Attach(func() { a.onLogin() })
	opMenu.Actions().Add(loginItem)

	// 预填上次登录信息
	if sess, err := loadSession(); err == nil {
		a.hostEdit.SetText(sess.Host)
		a.userEdit.SetText(sess.User)
		a.passEdit.SetText(sess.Password)
	} else {
		a.hostEdit.SetText("192.168.1.100")
	}

	// 子类化主窗口窗口过程，用于接收后台线程消息（必须在窗口创建后）
	theApp = a
	if err := a.installSubclass(); err != nil {
		return nil, err
	}

	return a, nil
}

// onLogin 登录
func (a *App) onLogin() {
	host := strings.TrimSpace(a.hostEdit.Text())
	user := strings.TrimSpace(a.userEdit.Text())
	pass := a.passEdit.Text()
	if host == "" {
		host = "192.168.1.100"
	}
	if user == "" || pass == "" {
		walk.MsgBox(a, "提示", "请输入账号和密码", walk.MsgBoxIconInformation)
		return
	}

	a.loginBtn.SetEnabled(false)
	a.loginBtn.SetText("登录中...")
	a.setStatus("正在登录 " + host + " ...")

	// 会话失效时自动重登一次
	doLogin := func() error {
		c := NewClient(host)
		if err := c.Login(user, pass); err != nil {
			return err
		}
		a.client = c
		a.host, a.user, a.pass = host, user, pass
		return nil
	}

	go func() {
		if err := doLogin(); err != nil {
			a.post("login_err", err, nil)
			return
		}
		// 保存会话缓存（含密码，本机 0600）
		saveSession(Session{
			Host: host, User: user, Password: pass,
			Token: a.client.token, Cookie: a.client.cookie, SavedAt: time.Now(),
		})
		a.post("login_ok", nil, nil)
	}()
}

// shortErr 压缩错误信息用于一行提示
func shortErr(err error) string {
	s := err.Error()
	if i := strings.Index(s, ": "); i >= 0 && strings.Count(s, ": ") > 1 {
		if j := strings.LastIndex(s, ": "); j >= 0 {
			s = s[j+2:]
		}
	}
	if len(s) > 80 {
		s = s[:80] + "..."
	}
	return s
}

// ---------- main ----------

func main() {
	a, err := newApp()
	if err != nil {
		fmt.Fprintln(os.Stderr, "初始化界面失败:", err)
		os.Exit(1)
	}
	a.Show()
	a.Run()
}
