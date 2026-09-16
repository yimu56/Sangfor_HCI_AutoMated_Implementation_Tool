// sangfor-ifaces: 深信服设备 vapi 接口客户端 —— 自动登录、会话缓存、交互式查询
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
// 修改网口（写操作，来自 修改网络接口.har）:
//
//  1. POST /vapi/extjs/vs/vs_config/verfity_passwd   password=RSA_PKCS1v15(明文密码)
//     （注意：此处不拼接 secret，已实测确认）
//  2. PUT  /vapi/json/nodes/<hostid>/network/ifaces/<iface>
//     desc=&ip=&netmask=&gateway=&link_mode=6&mtu=1500&mac=<mac>&custom_name=
//     → 返回 data.task_id
//  3. GET  /vapi/json/log/process?upid=<task_id>     轮询任务（process=0 表示进行中）
//     安全约束: 交互模式必须展示变更对比并要求输入 YES 才提交;
//     脚本模式默认 dry-run，需显式加 -confirm 才真正写入。
//
// 运行方式:
//
//	直接双击/运行（无参数）: 交互式菜单
//	  - 首次运行要求输入设备地址、账号、密码，登录后凭据缓存到本地会话文件
//	  - 再次运行自动使用缓存会话（失效时自动要求重新登录）
//	  - 执行完功能后回到菜单继续选择，Ctrl+C 或输入 0 退出
//	命令行参数（脚本模式，执行一次后退出）:
//	  sangfor-ifaces -host 192.168.1.100 -user admin -pass 'demo-pass' [-mode all|ifaces|vms]
//	环境变量: SANGFOR_HOST / SANGFOR_USER / SANGFOR_PASS
//
// 会话缓存文件: 可执行文件同目录下 .sangfor-session.json（仅存 token/cookie，不存密码）
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
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

// NodeIfaces /vapi/json/cluster/network/ifaces 返回的单个节点
type NodeIfaces struct {
	NodeName   string  `json:"node_name"`
	NodeID     string  `json:"node_id"`
	NodeStatus int     `json:"node_status"`
	Data       []Iface `json:"data"`
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
}

// Speed 网口速率。
// 注意: Negotiation 是"是否自动协商"的开关(1=自动协商, 0=强制)，不是链路模式编号，
// 切勿把它当成 link_mode 提交（曾因此把网口设成 10M）。
type Speed struct {
	Negotiation int `json:"negotiation"`
	Value       int `json:"value"` // Mbps, 0=未协商
	Duplex      int `json:"duplex"`
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
	baseURL string
	token   string // CSRFPreventionToken
	cookie  string // LoginAuthCookie=<ticket>（登录后由 Set-Cookie 获得）
	pass    string // 当前账号密码（内存持有，写操作校验用，避免二次输入）
	rsaKey  *rsa.PublicKey
	http    *http.Client
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
	fmt.Printf("登录成功, 用户: %s, 角色: %s\n", tk.Username, tk.UserRole)
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

// Session 本地缓存的登录会话（不含密码）
type Session struct {
	Host     string    `json:"host"`
	User     string    `json:"user"`
	Token    string    `json:"csrf_token"`
	Cookie   string    `json:"login_cookie"`
	Password string    `json:"password,omitempty"` // 仅本机 0600 权限保存，供自动校验
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

// ---------- 展示 ----------

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

func showHardware(client *Client) error {
	nodes, err := client.GetNodeList()
	if err != nil {
		return err
	}
	for _, n := range nodes {
		if !strings.HasPrefix(n.Hostid, "host-") {
			continue
		}
		info, err := client.GetHostInfo(n.Hostid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "获取节点 %s 硬件信息失败: %v\n", n.Node, err)
			continue
		}
		printHostInfo(info)
	}
	return nil
}

func printHostInfo(info *HostInfo) {
	fmt.Printf("\n═══ 节点: %s (%s)  状态: %s ═══\n", info.Name, info.IP, info.Status)
	fmt.Printf("  序列号: %s    机型: %s (%s)\n", orDash(info.SerialNumber), orDash(info.ServerModel), orDash(info.HardwareType))
	fmt.Printf("  系统版本: %s    开机时长: %s    运行VM: %d\n", orDash(info.OSVersion), uptimeText(info.Uptime), info.RunningVMs)

	cs := info.CPUStatus
	fmt.Printf("  CPU: %s\n", orDash(cs.CPUModel))
	fmt.Printf("       %d路 %d核 %d线程  %sMHz  缓存 %s  使用率 %s%%\n",
		cs.Sockets, cs.Cores, cs.Threads, cs.Mhz, orDash(cs.Cache), ratioPct(cs.Ratio))
	if len(cs.Temps) > 0 {
		parts := make([]string, 0, len(cs.Temps))
		for _, t := range cs.Temps {
			parts = append(parts, fmt.Sprintf("%s=%d°C", t.Name, t.Value))
		}
		fmt.Printf("       温度: %s\n", strings.Join(parts, "  "))
	}

	fmt.Printf("  内存: 总计 %s  空闲 %s  使用率 %s%%\n",
		gib(info.MemStatus.Total), gib(info.MemStatus.Free), ratioPct(info.MemStatus.Ratio))
	ml := info.MemLayout.Compute
	if ml.ConfTotalByte > 0 {
		fmt.Printf("        虚拟化内存: 配置总额 %s (超分 %d%%)  预分配 %s  超用 %s  可超用 %s\n",
			gib(ml.ConfTotalByte), ml.ConfOverPercent, gib(ml.PreallocatedByte), gib(ml.OverusedByte), gib(ml.OverusableByte))
	}
	cc := info.ConfCPU
	if cc.ConfTotalVcore > 0 {
		fmt.Printf("  vCPU 超分: 已配 %d/%d vCore (物理 %d, 超分 %d%%), 使用率 %s%%\n",
			cc.ConfUsedVcore, cc.ConfTotalVcore, cc.TotalCPUVcore, cc.CPUOverPercent, ratioPct(cc.ConfUsedRate))
	}

	if len(info.StorageStatus) > 0 {
		fmt.Println("  存储:")
		for _, st := range info.StorageStatus {
			fmt.Printf("    %-10s (%s)  总 %s  已用 %s  可用 %s  %s%%\n",
				st.Name, st.Type, gib(st.Total), gib(st.Used), gib(st.Free), ratioPct(st.Ratio))
		}
	}

	if len(info.RaidCardStatus) > 0 {
		ctrls := make([]string, 0, len(info.RaidCardStatus))
		for name, rc := range info.RaidCardStatus {
			ctrls = append(ctrls, fmt.Sprintf("%s: %s [%s] (物理盘 %s)", name, rc.ControllerModel, rc.ControllerStat, rc.PhysicalDevNum))
		}
		fmt.Printf("  RAID 卡: %s\n", strings.Join(ctrls, "  |  "))
	}

	if nc := info.NetCardsStatus; nc.Num > 0 {
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
		fmt.Printf("  网卡: 共 %d 个 (%s)\n", nc.Num, strings.Join(parts, ", "))
	}

	if len(info.Fan) > 0 {
		parts := make([]string, 0, len(info.Fan))
		for _, f := range info.Fan {
			parts = append(parts, fmt.Sprintf("%s=%drpm[%s]", f.Name, f.Speed, f.Status))
		}
		fmt.Printf("  风扇: %s\n", strings.Join(parts, "  "))
	}
	if len(info.Power) > 0 {
		parts := make([]string, 0, len(info.Power))
		for _, p := range info.Power {
			parts = append(parts, fmt.Sprintf("%s (%s)", orDash(p.ModelName), orDash(p.Vendor)))
		}
		fmt.Printf("  电源: %s\n", strings.Join(parts, "  |  "))
	}
}

func showNodes(client *Client) error {
	nodes, err := client.GetNodeList()
	if err != nil {
		return err
	}
	fmt.Println("\n集群节点:")
	for _, n := range nodes {
		tag := ""
		if n.Master == 1 {
			tag = " [主节点]"
		}
		fmt.Printf("  %-20s %-12s 状态:%s%s\n", n.Node, n.Hostid, n.Status, tag)
	}
	return nil
}

func showIfaces(client *Client) error {
	nodes, err := client.GetNodeList()
	if err != nil {
		return err
	}
	for _, n := range nodes {
		if !strings.HasPrefix(n.Hostid, "host-") {
			continue
		}
		ni, err := client.GetIfaces(n.Hostid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "获取节点 %s 网口信息失败: %v\n", n.Node, err)
			continue
		}
		printNodeIfaces(ni)
	}
	return nil
}

func printNodeIfaces(ni *NodeIfaces) {
	fmt.Printf("\n节点: %s (%s)  状态: %d\n", ni.NodeName, ni.NodeID, ni.NodeStatus)
	fmt.Printf("%-8s %-18s %-16s %-16s %-16s %-6s %-16s %-8s %-30s %s\n",
		"网口", "MAC", "IP", "掩码", "网关", "状态", "速率", "模式", "角色", "备注")
	for _, f := range ni.Data {
		name := f.Name
		if f.CustomName != "" {
			name = f.Name + "(" + f.CustomName + ")"
		}
		remark := f.BDRSwitch
		if remark == "" {
			remark = f.Desc
		}
		fmt.Printf("%-8s %-18s %-16s %-16s %-16s %-6s %-16s %-8s %-30s %s\n",
			name, f.MAC, orDash(f.IP), orDash(f.Netmask), orDash(f.Gateway),
			ifaceStatus(f.Status), speedText(f.Speed.Value, f.Speed.Duplex),
			f.IfaceMode, rolesText(f.Roles), remark)
	}
}

func showVMs(client *Client) error {
	groups, err := client.GetVMList()
	if err != nil {
		return err
	}
	printVMList(groups)
	return nil
}

func printVMList(groups []VMGroup) {
	total := 0
	running := 0
	for _, g := range groups {
		fmt.Printf("\n分组: %s  所有者: %s  数量: %d\n", g.Name, g.Owner, g.DirectVMNum)
		fmt.Printf("%-24s %-18s %-9s %-4s %-8s %-8s %-8s %-30s %s\n",
			"名称", "vmid", "状态", "vCPU", "内存", "内存占用", "磁盘", "操作系统", "主机")
		for _, v := range g.Data {
			total++
			if v.RunningStatus() {
				running++
			}
			fmt.Printf("%-24s %-18d %-9s %-4d %-8s %-8s %-8s %-30s %s\n",
				truncate(v.Name, 22), v.VMID, v.Status, v.CPUs,
				gib(v.MemTotal), gib(v.MemUsed), gib(v.DiskUsed),
				orDash(v.OSDistribution), strings.Trim(v.HostConfig, "<>"))
		}
	}
	fmt.Printf("\n合计: %d 台虚拟机, %d 台运行中\n", total, running)
}

// ---------- 修改网口配置（交互式，含强制确认） ----------

// pickHostNode 选择要操作的节点
func pickHostNode(reader *bufio.Reader, client *Client) (*ClusterNode, error) {
	nodes, err := client.GetNodeList()
	if err != nil {
		return nil, err
	}
	var hosts []ClusterNode
	for _, n := range nodes {
		if strings.HasPrefix(n.Hostid, "host-") {
			hosts = append(hosts, n)
		}
	}
	if len(hosts) == 0 {
		return nil, errors.New("未找到可操作的节点")
	}
	if len(hosts) == 1 {
		return &hosts[0], nil
	}
	fmt.Println("\n请选择节点:")
	for i, n := range hosts {
		fmt.Printf("  %d) %s (%s)\n", i+1, n.Node, n.Hostid)
	}
	for {
		s := prompt(reader, fmt.Sprintf("请输入序号 [1-%d]: ", len(hosts)))
		var idx int
		if _, err := fmt.Sscanf(s, "%d", &idx); err == nil && idx >= 1 && idx <= len(hosts) {
			return &hosts[idx-1], nil
		}
		fmt.Println("输入无效，请重试。")
	}
}

// setIfaceFlow 交互式修改网口配置：展示现状 -> 输入新值 -> 强制确认 -> 密码校验 -> 提交并等待
func setIfaceFlow(reader *bufio.Reader, client *Client, sess *Session) error {
	node, err := pickHostNode(reader, client)
	if err != nil {
		return err
	}
	ni, err := client.GetIfaces(node.Hostid)
	if err != nil {
		return err
	}

	fmt.Printf("\n节点 %s 的网口列表:\n", node.Node)
	for i, f := range ni.Data {
		fmt.Printf("  %d) %-6s %-18s %-16s %s\n", i+1, f.Name, f.MAC, orDash(f.IP), ifaceStatus(f.Status))
	}

	// 选择网口
	var target *Iface
	for target == nil {
		s := prompt(reader, "请输入要修改的网口名称或序号: ")
		if s == "" {
			return errors.New("已取消")
		}
		var idx int
		if _, err := fmt.Sscanf(s, "%d", &idx); err == nil && idx >= 1 && idx <= len(ni.Data) {
			target = &ni.Data[idx-1]
			break
		}
		for i := range ni.Data {
			if strings.EqualFold(ni.Data[i].Name, s) {
				target = &ni.Data[i]
				break
			}
		}
		if target == nil {
			fmt.Println("未找到该网口，请重试。")
		}
	}

	// 自动协商取值按该网卡推导（各网卡不同，不写死 6）
	autoVal, autoOK := autoLinkMode(target)
	curLink := fmt.Sprintf("%d", target.LinkMode)
	curLinkLabel := fmt.Sprintf("模式%d", target.LinkMode)
	if autoOK {
		curLinkLabel = linkModeLabel(target.LinkMode, autoVal)
	}
	curMTU := fmt.Sprintf("%d", target.MTU)

	// 展示当前配置
	fmt.Printf("\n当前配置 [%s]:\n", target.Name)
	fmt.Printf("  IP: %s    掩码: %s    网关: %s\n", orDash(target.IP), orDash(target.Netmask), orDash(target.Gateway))
	fmt.Printf("  MTU: %d   链路模式: %s   自定义名称: %s    备注: %s\n",
		target.MTU, curLinkLabel, orDash(target.CustomName), orDash(target.Desc))

	// 默认值：优先用户上一次输入的内容，其次设备当前值
	last, hasLast := findLastInput(client.baseURL, target.Name)
	if hasLast {
		fmt.Printf("  默认值取自上次修改 %s 时的输入（%s）\n", last.Iface, last.SavedAt.Format("2006-01-02 15:04"))
	}
	defIP, defMask, defGW, defMTU, defLink, defName, defDesc := target.IP, target.Netmask, target.Gateway, curMTU, curLink, target.CustomName, target.Desc
	if hasLast {
		defIP, defMask, defGW, defMTU, defName, defDesc = last.IP, last.Netmask, last.Gateway, last.MTU, last.CustomName, last.Desc
		if last.LinkMode != "" {
			defLink = last.LinkMode
		}
	}
	fmt.Println("  提示: 回车采用默认值 / 输入 - 清空 / 输入 ! 采用设备当前值")

	// 输入新值
	newIP := promptField(reader, "新 IP", defIP, target.IP)
	newMask := promptField(reader, "新掩码", defMask, target.Netmask)
	newGW := promptField(reader, "新网关", defGW, target.Gateway)
	newMTU := promptField(reader, "新 MTU", defMTU, curMTU)
	newName := promptField(reader, "新自定义名称", defName, target.CustomName)
	newDesc := promptField(reader, "新备注", defDesc, target.Desc)

	// 链路模式：列出该网卡支持的模式，默认保持当前值（即保持自动协商）
	fmt.Printf("\n该网卡支持的模式: %s\n", modesText(target))
	newLink := promptField(reader, "新链路模式(数字)", defLink, curLink)
	if newLink == "" {
		newLink = curLink
	}

	cfg := IfaceConfig{
		Desc:       newDesc,
		IP:         newIP,
		Netmask:    newMask,
		Gateway:    newGW,
		LinkMode:   newLink,
		MTU:        newMTU,
		MAC:        target.MAC,
		CustomName: newName,
	}

	// 变更对比
	changes := []string{}
	if newIP != target.IP {
		changes = append(changes, fmt.Sprintf("  IP:        %s  ->  %s", orDash(target.IP), orDash(newIP)))
	}
	if newMask != target.Netmask {
		changes = append(changes, fmt.Sprintf("  掩码:      %s  ->  %s", orDash(target.Netmask), orDash(newMask)))
	}
	if newGW != target.Gateway {
		changes = append(changes, fmt.Sprintf("  网关:      %s  ->  %s", orDash(target.Gateway), orDash(newGW)))
	}
	if newMTU != curMTU {
		changes = append(changes, fmt.Sprintf("  MTU:       %d  ->  %s", target.MTU, newMTU))
	}
	if newLink != curLink {
		newLabel := fmt.Sprintf("模式%s", newLink)
		if v, err := strconv.Atoi(newLink); err == nil {
			newLabel = linkModeLabel(v, autoVal)
		}
		changes = append(changes, fmt.Sprintf("  链路模式:  %s  ->  %s", curLinkLabel, newLabel))
	}
	if newName != target.CustomName {
		changes = append(changes, fmt.Sprintf("  自定义名:  %s  ->  %s", orDash(target.CustomName), orDash(newName)))
	}
	if newDesc != target.Desc {
		changes = append(changes, fmt.Sprintf("  备注:      %s  ->  %s", orDash(target.Desc), orDash(newDesc)))
	}
	if len(changes) == 0 {
		fmt.Println("\n未检测到任何变更，已取消操作。")
		return nil
	}

	fmt.Printf("\n即将对节点 %s 的网口 %s 应用以下变更:\n", node.Node, target.Name)
	for _, c := range changes {
		fmt.Println(c)
	}
	fmt.Println()
	fmt.Println("⚠️ 此操作非常危险，可能导致网络中断或不可逆的配置变更！")
	fmt.Println("   网口 IP/掩码/网关变更后，依赖该地址的业务与管理连接会立即中断。")
	if target.IP == node.IP || target.IP == node.Node {
		fmt.Println("   ⚠️ 注意：该网口当前承载设备管理地址，修改后本机将无法访问设备！")
	}
	confirm := prompt(reader, fmt.Sprintf("确认执行请精确输入 YES（输入 %s 取消）: ", target.Name))
	if confirm != "YES" {
		fmt.Println("已取消操作。")
		return nil
	}

	// 密码校验：优先使用登录时记住的密码，自动完成（无需二次输入）
	if client.pass == "" {
		// 本次运行没有可用密码（例如直接复用缓存会话启动），询问一次并记住
		client.pass = prompt(reader, "首次操作需要密码（之后自动使用）: ")
		sess.Password = client.pass
		saveSession(*sess)
	}
	fmt.Println("正在自动校验密码...")
	if err := client.VerifyPassword(client.pass); err != nil {
		// 密码已变更或错误：清除缓存密码后让用户重新输入一次
		fmt.Printf("自动校验失败(%v), 请重新输入密码。\n", shortErr(err))
		client.pass = ""
		sess.Password = ""
		saveSession(*sess)
		client.pass = prompt(reader, "请输入当前账号密码: ")
		if err := client.VerifyPassword(client.pass); err != nil {
			return err
		}
		sess.Password = client.pass
		saveSession(*sess)
	}
	fmt.Println("密码校验通过，正在提交修改...")

	taskID, err := client.SetIface(node.Hostid, target.Name, cfg)
	if err != nil {
		return err
	}
	fmt.Printf("任务已提交: %s\n等待设备执行...\n", taskID)

	msg, err := client.WaitTask(taskID, 2*time.Minute)
	if err != nil {
		return err
	}
	fmt.Printf("执行结果: %s\n", orDash(msg))

	// 记录本次输入，作为下次的默认值
	saveLastInput(LastInput{
		Host: client.baseURL, Iface: target.Name,
		IP: newIP, Netmask: newMask, Gateway: newGW, MTU: newMTU,
		LinkMode: newLink, CustomName: newName, Desc: newDesc,
		SavedAt: time.Now(),
	})

	// 回读一次确认
	if ni2, err := client.GetIfaces(node.Hostid); err == nil {
		for _, f := range ni2.Data {
			if f.Name == target.Name {
				fmt.Printf("当前 [%s]: IP=%s 掩码=%s 网关=%s\n",
					f.Name, orDash(f.IP), orDash(f.Netmask), orDash(f.Gateway))
				break
			}
		}
	}
	return nil
}

// promptField 字段输入。def=回车采用的默认值(通常是上次输入值)，cur=设备当前值。
// 输入 "-" 清空, 输入 "!" 采用设备当前值, 其他为自定义新值。
func promptField(reader *bufio.Reader, label, def, cur string) string {
	label2 := fmt.Sprintf("%s [%s]: ", label, orDash(def))
	if def != cur {
		label2 = fmt.Sprintf("%s [%s | 设备当前:%s]: ", label, orDash(def), orDash(cur))
	}
	s := prompt(reader, label2)
	switch s {
	case "":
		return def
	case "-":
		return ""
	case "!":
		return cur
	default:
		return s
	}
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
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// isAuthError 判断是否为鉴权失效（401）
func isAuthError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "HTTP 401")
}

// ---------- 交互模式 ----------

// prompt 读取一行用户输入（EOF 时优雅退出，避免死循环）
func prompt(reader *bufio.Reader, label string) string {
	fmt.Print(label)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		fmt.Println("\n输入已结束, 已退出。")
		os.Exit(0)
	}
	return strings.TrimSpace(line)
}

// doLoginInteractive 交互式登录，返回登录用户名
func doLoginInteractive(reader *bufio.Reader, client *Client) (string, string) {
	for {
		user := prompt(reader, "请输入账号: ")
		pass := prompt(reader, "请输入密码: ")
		if user == "" || pass == "" {
			fmt.Println("账号密码不能为空，请重试。")
			continue
		}
		if err := client.Login(user, pass); err != nil {
			fmt.Println("登录失败:", err)
			fmt.Println("请重试。")
			continue
		}
		return user, pass
	}
}

// reloginWithFallback 会话失效后重新登录:
// 优先尝试默认账号 admin/admin, 失败再由用户手动输入; 返回登录用户名
func reloginWithFallback(reader *bufio.Reader, client *Client) (string, string) {
	fmt.Println("正在尝试默认账号 admin/admin ...")
	if err := client.Login("admin", "admin"); err != nil {
		fmt.Printf("默认账号登录失败(%v), 请手动输入。\n", shortErr(err))
		return doLoginInteractive(reader, client)
	}
	fmt.Println("已使用默认账号 admin 自动登录。")
	return "admin", "admin"
}

// shortErr 压缩错误信息用于一行提示
func shortErr(err error) string {
	s := err.Error()
	if i := strings.Index(s, ": "); i >= 0 && strings.Count(s, ": ") > 1 {
		// 保留最后一段关键信息
		if j := strings.LastIndex(s, ": "); j >= 0 {
			s = s[j+2:]
		}
	}
	if len(s) > 80 {
		s = s[:80] + "..."
	}
	return s
}

// runAction 执行功能，遇 401 自动重新登录并重试一次
func runAction(reader *bufio.Reader, client *Client, sess *Session, name string, action func() error) {
	fmt.Printf("\n===== %s =====\n", name)
	err := action()
	if isAuthError(err) {
		fmt.Println("会话已过期，需要重新登录。")
		clearSession()
		client.token, client.cookie = "", ""
		user, pass := reloginWithFallback(reader, client)
		sess.User, sess.Token, sess.Cookie = user, client.token, client.cookie
		sess.Password, sess.SavedAt = pass, time.Now()
		saveSession(*sess)
		if err := action(); err != nil {
			fmt.Fprintln(os.Stderr, "执行失败:", err)
		}
	} else if err != nil {
		fmt.Fprintln(os.Stderr, "执行失败:", err)
	}
}

// interactiveMode 交互式主循环
func interactiveMode(hostFlag string) {
	reader := bufio.NewReader(os.Stdin)
	sess, _ := loadSession()

	// 设备地址：参数 > 缓存 > 手动输入(默认 192.168.1.100)
	host := hostFlag
	if host == "" {
		host = sess.Host
	}
	if host == "" {
		host = prompt(reader, "请输入设备地址 [192.168.1.100]: ")
		if host == "" {
			host = "192.168.1.100"
		}
	}

	client := NewClient(host)
	fmt.Printf("设备: %s\n", host)

	// 1. 检测缓存的 token
	if sess.Host == host && sess.Token != "" && sess.Cookie != "" {
		client.token, client.cookie = sess.Token, sess.Cookie
		client.pass = sess.Password // 复用缓存的密码，写操作时无需二次输入
		fmt.Printf("检测到缓存会话 (用户: %s, 保存于: %s)，正在验证...\n",
			sess.User, sess.SavedAt.Format("2006-01-02 15:04"))
		if _, err := client.GetNodeList(); err == nil {
			fmt.Println("缓存会话有效。")
		} else {
			fmt.Println("缓存会话已失效，需要重新登录。")
			client.token, client.cookie = "", ""
			user, pass := reloginWithFallback(reader, client)
			sess = Session{Host: host, User: user, Token: client.token,
				Cookie: client.cookie, Password: pass, SavedAt: time.Now()}
			saveSession(sess)
		}
	} else {
		// 2. 无缓存，要求输入账号密码
		fmt.Println("未检测到有效缓存会话，请登录。")
		user, pass := doLoginInteractive(reader, client)
		sess = Session{Host: host, User: user, Token: client.token,
			Cookie: client.cookie, Password: pass, SavedAt: time.Now()}
		saveSession(sess)
	}

	// 3. 功能菜单循环
	for {
		fmt.Println(`
================ 功能菜单 ================
  1. 集群节点列表
  2. 网口信息
  3. 虚拟机列表
  4. 全部查询 (节点+网口+虚拟机)
  5. 硬件信息 (CPU/内存/存储/RAID/风扇)
  6. 修改网口配置 ⚠ 写操作
  7. 切换账号重新登录
  0. 退出
  (Ctrl+C 随时可退出)
==========================================`)
		choice := prompt(reader, "请选择功能: ")
		switch choice {
		case "1":
			runAction(reader, client, &sess, "集群节点列表", func() error { return showNodes(client) })
		case "2":
			runAction(reader, client, &sess, "网口信息", func() error { return showIfaces(client) })
		case "3":
			runAction(reader, client, &sess, "虚拟机列表", func() error { return showVMs(client) })
		case "4":
			runAction(reader, client, &sess, "全部查询", func() error {
				if err := showNodes(client); err != nil {
					return err
				}
				if err := showIfaces(client); err != nil {
					return err
				}
				return showVMs(client)
			})
		case "5":
			runAction(reader, client, &sess, "硬件信息", func() error { return showHardware(client) })
		case "6":
			runAction(reader, client, &sess, "修改网口配置", func() error { return setIfaceFlow(reader, client, &sess) })
		case "7":
			clearSession()
			client.token, client.cookie, client.pass = "", "", ""
			user, pass := doLoginInteractive(reader, client)
			sess = Session{Host: host, User: user, Token: client.token,
				Cookie: client.cookie, Password: pass, SavedAt: time.Now()}
			saveSession(sess)
		case "0", "q", "quit", "exit":
			client.Logout()
			fmt.Println("已退出。")
			return
		case "":
			// 空输入，重新显示菜单
		default:
			fmt.Println("无效选项，请重新输入。")
		}
	}
}

// ---------- 一次性脚本模式 ----------

// setIfaceOpts 脚本模式修改网口的参数
type setIfaceOpts struct {
	host, user, pass, node, iface string
	ip, netmask, gateway, mtu     string
	linkMode                      string
	customName, desc              string
	confirm                       bool
}

// runSetIfaceOnce 脚本模式修改网口：默认只做 dry-run 对比，加 -confirm 才真正提交
func runSetIfaceOnce(o setIfaceOpts) int {
	client := NewClient(o.host)
	if err := client.Login(o.user, o.pass); err != nil {
		fmt.Fprintln(os.Stderr, "自动登录失败:", err)
		return 1
	}

	nodes, err := client.GetNodeList()
	if err != nil {
		fmt.Fprintln(os.Stderr, "获取节点列表失败:", err)
		return 1
	}
	nodeID := o.node
	if nodeID == "" {
		for _, n := range nodes {
			if strings.HasPrefix(n.Hostid, "host-") {
				nodeID = n.Hostid
				break
			}
		}
	}
	if nodeID == "" {
		fmt.Fprintln(os.Stderr, "未找到可操作节点，可用 -node 指定")
		return 1
	}

	ni, err := client.GetIfaces(nodeID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "获取网口信息失败:", err)
		return 1
	}
	var cur *Iface
	for i := range ni.Data {
		if strings.EqualFold(ni.Data[i].Name, o.iface) {
			cur = &ni.Data[i]
			break
		}
	}
	if cur == nil {
		fmt.Fprintf(os.Stderr, "节点 %s 上未找到网口 %s\n", nodeID, o.iface)
		return 1
	}

	cfg := IfaceConfig{
		Desc:       cur.Desc,
		IP:         cur.IP,
		Netmask:    cur.Netmask,
		Gateway:    cur.Gateway,
		LinkMode:   fmt.Sprintf("%d", cur.LinkMode),
		MTU:        fmt.Sprintf("%d", cur.MTU),
		MAC:        cur.MAC,
		CustomName: cur.CustomName,
	}
	if o.ip != "" {
		cfg.IP = o.ip
	}
	if o.netmask != "" {
		cfg.Netmask = o.netmask
	}
	if o.gateway != "" {
		cfg.Gateway = o.gateway
	}
	if o.mtu != "" {
		cfg.MTU = o.mtu
	}
	if o.linkMode != "" {
		cfg.LinkMode = o.linkMode
	}
	if o.customName != "" {
		cfg.CustomName = o.customName
	}
	if o.desc != "" {
		cfg.Desc = o.desc
	}

	fmt.Printf("\n目标: 节点 %s 网口 %s\n", nodeID, cur.Name)
	av, aok := autoLinkMode(cur)
	curLabel := fmt.Sprintf("模式%d", cur.LinkMode)
	if aok {
		curLabel = linkModeLabel(cur.LinkMode, av)
	}
	fmt.Printf("  当前: IP=%s 掩码=%s 网关=%s MTU=%d 链路模式=%s\n",
		orDash(cur.IP), orDash(cur.Netmask), orDash(cur.Gateway), cur.MTU, curLabel)
	fmt.Printf("  变更: IP=%s 掩码=%s 网关=%s MTU=%s 链路模式=%s\n",
		orDash(cfg.IP), orDash(cfg.Netmask), orDash(cfg.Gateway), cfg.MTU, cfg.LinkMode)

	if !o.confirm {
		fmt.Println("\n[DRY-RUN] 未提交任何修改。确认无误后加 -confirm 参数执行。")
		return 0
	}

	// 密码校验（与前端一致：修改前需重新校验密码）
	if err := client.VerifyPassword(o.pass); err != nil {
		fmt.Fprintln(os.Stderr, "密码校验失败:", err)
		return 1
	}
	fmt.Println("密码校验通过，提交修改...")

	taskID, err := client.SetIface(nodeID, cur.Name, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("任务已提交: %s\n", taskID)
	msg, err := client.WaitTask(taskID, 2*time.Minute)
	if err != nil {
		fmt.Fprintln(os.Stderr, "等待任务结果:", err)
		return 1
	}
	fmt.Printf("执行结果: %s\n", orDash(msg))
	return 0
}

func runOnce(host, user, pass, token, mode string) int {
	client := NewClient(host)

	// 鉴权: 优先使用已有 token, 否则自动登录
	if token != "" {
		client.token = token
		fmt.Println("使用提供的 token")
	} else {
		if err := client.Login(user, pass); err != nil {
			fmt.Fprintln(os.Stderr, "自动登录失败:", err)
			return 1
		}
	}

	if err := showNodes(client); err != nil {
		fmt.Fprintln(os.Stderr, "获取节点列表失败:", err)
		return 1
	}

	if mode == "all" || mode == "ifaces" {
		if err := showIfaces(client); err != nil {
			fmt.Fprintln(os.Stderr, "获取网口信息失败:", err)
			return 1
		}
	}
	if mode == "all" || mode == "vms" {
		if err := showVMs(client); err != nil {
			fmt.Fprintln(os.Stderr, "获取虚拟机列表失败:", err)
			return 1
		}
	}
	if mode == "all" || mode == "hw" {
		if err := showHardware(client); err != nil {
			fmt.Fprintln(os.Stderr, "获取硬件信息失败:", err)
			return 1
		}
	}
	return 0
}

// ---------- main ----------

func main() {
	// Ctrl+C 优雅退出
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Println("\n收到 Ctrl+C, 已退出。")
		os.Exit(0)
	}()

	host := flag.String("host", os.Getenv("SANGFOR_HOST"), "设备地址（交互模式下可作为默认值）")
	user := flag.String("user", os.Getenv("SANGFOR_USER"), "登录账号（提供 user+pass 则进入脚本模式）")
	pass := flag.String("pass", os.Getenv("SANGFOR_PASS"), "登录密码")
	token := flag.String("token", os.Getenv("SANGFOR_TOKEN"), "已有 CSRFPreventionToken（一般不需要，自动登录会获取）")
	mode := flag.String("mode", "all", "脚本模式查询内容: all / ifaces / vms / hw / setiface")

	// 修改网口（-mode setiface）专用参数
	fIface := flag.String("iface", "", "网口名称，如 eth4（-mode setiface）")
	fNode := flag.String("node", "", "节点 hostid，默认取第一个 host-* 节点")
	fIP := flag.String("ip", "", "新 IP 地址")
	fMask := flag.String("netmask", "", "新掩码")
	fGW := flag.String("gateway", "", "新网关")
	fMTU := flag.String("mtu", "", "新 MTU")
	fLink := flag.String("link-mode", "", "链路模式数字（默认保持当前值，自动协商请填该网卡支持列表中的自动协商值）")
	fName := flag.String("custom-name", "", "新自定义名称")
	fDesc := flag.String("desc", "", "新备注")
	fConfirm := flag.Bool("confirm", false, "修改网口时确认执行（不加则仅对比预览，不提交）")
	flag.Parse()

	// 修改网口脚本模式
	if *mode == "setiface" {
		if *host == "" || *user == "" || *pass == "" {
			fmt.Fprintln(os.Stderr, "修改网口需要 -host -user -pass，以及 -iface 与至少一个变更参数")
			os.Exit(1)
		}
		if *fIface == "" {
			fmt.Fprintln(os.Stderr, "缺少 -iface（网口名称），可先运行 -mode ifaces 查看")
			os.Exit(1)
		}
		os.Exit(runSetIfaceOnce(setIfaceOpts{
			host: *host, user: *user, pass: *pass, node: *fNode, iface: *fIface,
			ip: *fIP, netmask: *fMask, gateway: *fGW, mtu: *fMTU, linkMode: *fLink,
			customName: *fName, desc: *fDesc, confirm: *fConfirm,
		}))
	}

	// 脚本模式: host + (user+pass 或 token) 齐全时, 执行一次后退出
	if *host != "" && ((*user != "" && *pass != "") || *token != "") {
		os.Exit(runOnce(*host, *user, *pass, *token, *mode))
	}

	// 交互模式
	interactiveMode(*host)
}
