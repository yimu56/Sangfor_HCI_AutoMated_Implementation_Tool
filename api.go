package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

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

// do 发送表单请求（form-urlencoded）—— 只是 doBody 的薄封装。
//
// 收敛到 doBody 的意义：所有请求都从同一个出口发出，调试抓包（harcapture.go）
// 只需挂在这一个出口上就能覆盖"任何涉及网络的操作"。
func (c *Client) do(method, path string, form url.Values) ([]byte, http.Header, error) {
	if form == nil {
		return c.doBody(method, path, "", nil)
	}
	return c.doBody(method, path, "application/x-www-form-urlencoded; charset=UTF-8", []byte(form.Encode()))
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
