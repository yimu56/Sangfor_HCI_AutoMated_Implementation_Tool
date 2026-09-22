// netcfg.go: 深信服超融合 4 类网络配置（写操作）的接口层
//
// 本文件由以下 4 份抓包还原（真机 6 节点 VXLAN 集群 192.168.131.179）:
//
//	配置VXLAN的IP-edited.har   VXLAN IP 池（为 VXLAN 隧道承载口分配 VTEP 地址）
//	端口聚合-edited.har        创建聚合口（bond / channelN）
//	配置存储网.har             存储通信网口配置（vs_networksetting）
//	配置业务口.har             业务口（SDN 拓扑"物理出口"节点）
//
// 设计原则:
//  1. 读-校验-写-轮询-回读 五段式，写操作前必须能拿到"现网值"用于 diff
//  2. 请求体结构严格照抓包复刻，不做"看起来更合理"的改写
//  3. 任何不确定的取值（如 change_iface_type）保留抓包原值并显式注释，不臆测
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ---------- 通用：JSON 请求支持 ----------
//
// 原 do() 只支持 form-urlencoded。新增 4 个接口里有 3 个是 JSON body
// （vxlan-ip-pools / asan ifacecheck / sdn network-portal nodes），因此补充 JSON 通道。

// doBody 发送请求（可指定 Content-Type 与原始 body），是 do() 的底层实现
func (c *Client) doBody(method, path, contentType string, body []byte) ([]byte, http.Header, error) {
	var bodyReader *bytes.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
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
	// 业务请求阶段 Referer 指向主页面（与浏览器行为一致）
	if strings.Contains(path, "/vapi/") && c.cookie != "" {
		req.Header.Set("Referer", c.baseURL+"/")
	}

	// 调试抓包：这里是全部 HTTP 请求的唯一出口（do() 也走这里），
	// 只要配置文件里 debug.capture_har=true，任何涉及网络的操作都会被记录成 HAR。
	reqStart := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		harRecord(req, body, 0, nil, nil, time.Since(reqStart), err)
		return nil, nil, fmt.Errorf("请求 %s 失败: %w", path, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		harRecord(req, body, resp.StatusCode, resp.Header, nil, time.Since(reqStart), err)
		return nil, nil, err
	}
	harRecord(req, body, resp.StatusCode, resp.Header, respBody, time.Since(reqStart), nil)
	if resp.StatusCode != http.StatusOK {
		return respBody, resp.Header, fmt.Errorf("请求 %s 返回 HTTP %d: %s",
			path, resp.StatusCode, truncate(string(respBody), 200))
	}
	return respBody, resp.Header, nil
}

// callAPIJSON 以 JSON body 调用 vapi 接口并校验 success=1
func (c *Client) callAPIJSON(method, path string, payload interface{}) (*json.RawMessage, error) {
	var body []byte
	if payload != nil {
		var err error
		if body, err = json.Marshal(payload); err != nil {
			return nil, fmt.Errorf("序列化请求体失败: %w", err)
		}
	}
	raw, _, err := c.doBody(method, path, "application/json; charset=UTF-8", body)
	if err != nil {
		return nil, err
	}
	var api APIResponse
	if err := json.Unmarshal(raw, &api); err != nil {
		return nil, fmt.Errorf("解析 %s 响应失败: %w, body=%s", path, err, truncate(string(raw), 200))
	}
	if api.Success != 1 {
		return nil, fmt.Errorf("请求 %s 业务失败: success=%d errcode=%v tracing=%s",
			path, api.Success, derefStr(api.Errcode), api.ErrcodeTracing)
	}
	return api.Data, nil
}

// ---------- 通用：UUID v4 ----------

// NewUUIDv4 生成 RFC4122 v4 UUID。
//
// 业务口的拓扑节点 ID 由【客户端本地生成】：抓包中该值形如
// 6d1b0e3d-05ad-412f-b3e4-508eddf01a8f（第 3 组以 4 开头 = v4），
// 且后续任务日志里紧接着出现"创建拓扑节点/创建物理出口成功"，
// 说明服务端接受客户端指定的 ID，而不是先由服务端下发 ID。
func NewUUIDv4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// 退化路径：极端情况下用时间戳填充，保证唯一性
		now := time.Now().UnixNano()
		for i := 0; i < 8; i++ {
			b[i] = byte(now >> (8 * i))
		}
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ---------- 1. VXLAN IP 池 ----------
//
// 读: GET  /vapi/extjs/network/v1.0/vxlan-ip-pools?start=0&limit=20
//     → data.vxlan_ippools[] （注意: 列表在 vxlan_ippools，单条在 vxlan_ip_pool）
// 写: POST /vapi/extjs/network/v1.0/vxlan-ip-pools   (JSON)
//     {"vxlan_ip_pool":{"ip_range":[...],"netmask":"...","gateway":"","node_ids":[...],"description":""}}
//     → data.vxlan_ip_pool（含服务端算出的 node_ips 映射与 left_ip_number）

// VXLANNodeIP 某节点分配到的 VXLAN 承载 IP
type VXLANNodeIP struct {
	VXLANIP string `json:"vxlan_ip"`
	NodeID  string `json:"node_id"`
}

// VXLANIPPool VXLAN 承载 IP 池
type VXLANIPPool struct {
	ID           string        `json:"id"`
	IPRange      []string      `json:"ip_range"`
	Netmask      string        `json:"netmask"`
	Gateway      *string       `json:"gateway"` // 允许 null
	Description  string        `json:"description"`
	LeftIPNumber int           `json:"left_ip_number"`
	NodeIPs      []VXLANNodeIP `json:"node_ips"`
}

// vxlanIPPoolListResp 列表接口响应
type vxlanIPPoolListResp struct {
	IPPools []VXLANIPPool `json:"vxlan_ippools"`
	Total   int           `json:"total"`
}

// vxlanIPPoolCreateResp 创建接口响应
type vxlanIPPoolCreateResp struct {
	IPPool VXLANIPPool `json:"vxlan_ip_pool"`
}

// vxlanIPPoolCreateReq 创建请求体（字段顺序与抓包一致）
type vxlanIPPoolCreateReq struct {
	IPPool struct {
		IPRange     []string `json:"ip_range"`
		Netmask     string   `json:"netmask"`
		Gateway     string   `json:"gateway"`
		NodeIDs     []string `json:"node_ids"`
		Description string   `json:"description"`
	} `json:"vxlan_ip_pool"`
}

// GetVXLANIPPools 查询现网 VXLAN IP 池（用于 diff 与展示）
func (c *Client) GetVXLANIPPools() ([]VXLANIPPool, error) {
	raw, err := c.callAPI(http.MethodGet, "/vapi/extjs/network/v1.0/vxlan-ip-pools?start=0&limit=100", nil)
	if err != nil {
		return nil, err
	}
	var res vxlanIPPoolListResp
	if err := json.Unmarshal(*raw, &res); err != nil {
		return nil, fmt.Errorf("解析 VXLAN IP 池失败: %w", err)
	}
	return res.IPPools, nil
}

// CreateVXLANIPPool 创建/下发 VXLAN IP 池（写操作）
//
// ipRange 与 nodeIDs 一一对应（顺序即分配顺序），长度必须一致。
func (c *Client) CreateVXLANIPPool(ipRange []string, netmask, gateway string, nodeIDs []string, description string) (*VXLANIPPool, error) {
	if len(ipRange) == 0 {
		return nil, errors.New("IP 列表为空")
	}
	if len(nodeIDs) == 0 {
		return nil, errors.New("节点列表为空")
	}
	if len(ipRange) != len(nodeIDs) {
		return nil, fmt.Errorf("IP 数量(%d)与节点数量(%d)不一致：IP 池按顺序一对一分配到节点",
			len(ipRange), len(nodeIDs))
	}
	var req vxlanIPPoolCreateReq
	req.IPPool.IPRange = ipRange
	req.IPPool.Netmask = netmask
	req.IPPool.Gateway = gateway
	req.IPPool.NodeIDs = nodeIDs
	req.IPPool.Description = description

	raw, err := c.callAPIJSON(http.MethodPost, "/vapi/extjs/network/v1.0/vxlan-ip-pools", req)
	if err != nil {
		return nil, err
	}
	var res vxlanIPPoolCreateResp
	if err := json.Unmarshal(*raw, &res); err != nil {
		return nil, fmt.Errorf("解析创建结果失败: %w", err)
	}
	return &res.IPPool, nil
}

// DescribeNodeIPMap 把 node_ips 映射整理成 "节点 -> IP" 文本
func DescribeNodeIPMap(pool *VXLANIPPool, nodeName func(string) string) []string {
	if pool == nil {
		return nil
	}
	var out []string
	for _, ni := range pool.NodeIPs {
		name := ni.NodeID
		if nodeName != nil {
			if n := nodeName(ni.NodeID); n != "" {
				name = n
			}
		}
		out = append(out, fmt.Sprintf("%s → %s", name, ni.VXLANIP))
	}
	return out
}

// ---------- 2. 端口聚合（bond） ----------
//
// 写: POST /vapi/json/cluster/network/bonds   (form)
//     ifaces=[{"node_id":"host-xxx",
//              "bond":{"members":"eth4,eth6","mode":"lacp-layer34"},
//              "vlan":{},"iface":{},"fusion":{"fusion_enable":0}}]
//     → data.task_id
//
// 读: 没有独立的 bonds 查询接口，聚合口信息在 /cluster/network/ifaces 里
//     以 type=bond 出现（name=channelN，mode=聚合模式，members=成员口）。

// BondSpec 单节点聚合口配置
type BondSpec struct {
	NodeID       string
	Members      string // 逗号分隔，如 "eth4,eth6"
	Mode         string // 如 "lacp-layer34"
	FusionEnable int    // 0/1
}

// bond 抓包里各层级只有单键，用结构体复刻以免引入多余字段
type bondPayload struct {
	NodeID string `json:"node_id"`
	Bond   struct {
		Members string `json:"members"`
		Mode    string `json:"mode"`
	} `json:"bond"`
	VLAN   map[string]interface{} `json:"vlan"`
	Iface  map[string]interface{} `json:"iface"`
	Fusion struct {
		FusionEnable int `json:"fusion_enable"`
	} `json:"fusion"`
}

// 常见的聚合模式候选。lacp-layer34 是抓包实测值（也是管理口/业务口/存储口的现网模式）；
// 其余为设备同类产品常见取值，界面允许手工填写，避免因版本差异漏掉新模式。
var BondModeCandidates = []string{
	"lacp-layer34",
	"lacp-layer23",
	"active-backup",
	"balance-xor",
	"balance-rr",
	"broadcast",
}

// CreateBonds 批量创建聚合口（一次请求覆盖多节点，与设备页面行为一致）
func (c *Client) CreateBonds(specs []BondSpec) (string, error) {
	if len(specs) == 0 {
		return "", errors.New("未指定任何节点")
	}
	var items []bondPayload
	for _, s := range specs {
		if strings.TrimSpace(s.Members) == "" {
			return "", fmt.Errorf("节点 %s 未选择成员口", s.NodeID)
		}
		if strings.TrimSpace(s.Mode) == "" {
			return "", fmt.Errorf("节点 %s 未指定聚合模式", s.NodeID)
		}
		var it bondPayload
		it.NodeID = s.NodeID
		it.Bond.Members = s.Members
		it.Bond.Mode = s.Mode
		it.VLAN = map[string]interface{}{}
		it.Iface = map[string]interface{}{}
		it.Fusion.FusionEnable = s.FusionEnable
		items = append(items, it)
	}
	jsonBody, err := json.Marshal(items)
	if err != nil {
		return "", fmt.Errorf("序列化聚合口参数失败: %w", err)
	}
	raw, err := c.callAPI(http.MethodPost, "/vapi/json/cluster/network/bonds",
		url.Values{"ifaces": {string(jsonBody)}})
	if err != nil {
		return "", err
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

// ---------- 3. 存储网（存储通信网口配置） ----------
//
// 读  : GET  /vapi/extjs/vs/vs_config/vs_networksetting_get?add_host=0
//       → data[] 每节点 {host_name, service_ip, host_alias, host_ip, netmask,
//                        host_mask, nics[], vlan_id, type, hoststatus, used_rdma, is_new}
// 校验: POST /vapi/json/vs/vs_config/vs_check_arbiter_same_netip  (form)
//       change_iface_type=private&host_list=[...]  → data{warn_info,warn_level}
// 写  : POST /vapi/extjs/vs/vs_config/vs_networksetting_set     (form)
//       networksetting=[...]  → data 是【UPID 字符串】（不是 task_id 字段！）
// 判据: GET  /vapi/extjs/vs/vs_config/is_net_config  看 type 由 NONE → standard_network

// vsChangeIfaceType 严格取自抓包原值（配置存储网.har 中 change_iface_type=private）。
// 该字段语义在抓包里没有旁证，不臆测、不改写。
const vsChangeIfaceType = "private"

// VSNodeSetting 单节点存储通信网口配置
type VSNodeSetting struct {
	ServiceIP  string   `json:"service_ip"`  // 节点管理 IP（别名）
	Nics       []string `json:"nics"`        // 承载网口（如 channel3）
	HostStatus int      `json:"host_status"` // 主机是否在线 1=在线
	HostAlias  string   `json:"host_alias"`  // 节点管理 IP
	VLANID     int      `json:"vlan_id"`     // 0 表示不打 VLAN
	IsNew      string   `json:"is_new"`      // "1" 表示本次新增配置
	HostMask   string   `json:"host_mask"`   // 管理网掩码
	UsedRDMA   int      `json:"used_rdma"`
	Hoststatus int      `json:"hoststatus"` // 同上（设备同时返回两种拼写）
	HostName   string   `json:"host_name"`  // hostid
	Type       string   `json:"type"`       // standard_network / private ...
	Netmask    string   `json:"netmask"`    // 存储网掩码
	HostIP     string   `json:"host_ip"`    // 存储网 IP ← 本页要改的核心字段
}

// GetVSNetworkSetting 查询各节点当前的存储通信网口配置
func (c *Client) GetVSNetworkSetting() ([]VSNodeSetting, error) {
	raw, err := c.callAPI(http.MethodGet, "/vapi/extjs/vs/vs_config/vs_networksetting_get?add_host=0", nil)
	if err != nil {
		return nil, err
	}
	var list []VSNodeSetting
	if err := json.Unmarshal(*raw, &list); err != nil {
		return nil, fmt.Errorf("解析存储网配置失败: %w", err)
	}
	return list, nil
}

// NetConfigState /vapi/extjs/vs/vs_config/is_net_config
type NetConfigState struct {
	Type            string `json:"type"` // NONE / standard_network / private ...
	IsConfig        string `json:"is_config"`
	IsVSInitialized string `json:"is_vs_initialized"`
	NeedDetectIP    string `json:"need_detect_ip"`
	NeedReconfigNet string `json:"need_reconfig_network"`
	DetectIP        string `json:"detect_ip"`
	EnableDetectIP  string `json:"enable_detect_ip"`
	IsSingle        string `json:"is_single"`
	Raw             string `json:"-"`
}

// GetNetConfigState 查询存储网络配置状态（写操作后的回读判据）
func (c *Client) GetNetConfigState() (*NetConfigState, error) {
	raw, err := c.callAPI(http.MethodGet, "/vapi/extjs/vs/vs_config/is_net_config", nil)
	if err != nil {
		return nil, err
	}
	var st NetConfigState
	if err := json.Unmarshal(*raw, &st); err != nil {
		return nil, fmt.Errorf("解析网络配置状态失败: %w", err)
	}
	st.Raw = truncate(string(*raw), 300)
	return &st, nil
}

// marshalVSSettings 把节点配置序列化成抓包里那种 JSON 字符串（用于 form 参数）
func marshalVSSettings(list []VSNodeSetting) (string, error) {
	if len(list) == 0 {
		return "", errors.New("未指定任何节点")
	}
	b, err := json.Marshal(list)
	if err != nil {
		return "", fmt.Errorf("序列化存储网参数失败: %w", err)
	}
	return string(b), nil
}

// CheckArbiterSameNetIP 提交前的网段冲突校验（与设备页面一致）
//
// 返回 warn_info / warn_level；warn_level > 0 时应把警告展示给用户再决定是否继续。
func (c *Client) CheckArbiterSameNetIP(list []VSNodeSetting) (string, int, error) {
	payload, err := marshalVSSettings(list)
	if err != nil {
		return "", 0, err
	}
	raw, err := c.callAPI(http.MethodPost, "/vapi/json/vs/vs_config/vs_check_arbiter_same_netip",
		url.Values{
			"change_iface_type": {vsChangeIfaceType},
			"host_list":         {payload},
		})
	if err != nil {
		return "", 0, err
	}
	var res struct {
		WarnInfo  string `json:"warn_info"`
		WarnLevel int    `json:"warn_level"`
	}
	if err := json.Unmarshal(*raw, &res); err != nil {
		return "", 0, fmt.Errorf("解析校验结果失败: %w", err)
	}
	return res.WarnInfo, res.WarnLevel, nil
}

// SetVSNetworkSetting 下发存储通信网口配置（写操作）
//
// 注意: 该接口 data 直接是 UPID 字符串（如 UPID:host-xxx:...:添加主机::admin@vtp:），
// 不是 {"task_id":...}，需把它交给 WaitTask 轮询。
func (c *Client) SetVSNetworkSetting(list []VSNodeSetting) (string, error) {
	payload, err := marshalVSSettings(list)
	if err != nil {
		return "", err
	}
	raw, err := c.callAPI(http.MethodPost, "/vapi/extjs/vs/vs_config/vs_networksetting_set",
		url.Values{"networksetting": {payload}})
	if err != nil {
		return "", err
	}
	var upid string
	if err := json.Unmarshal(*raw, &upid); err != nil {
		return "", fmt.Errorf("解析任务号失败（期望 UPID 字符串）: %w, body=%s",
			err, truncate(string(*raw), 200))
	}
	if strings.TrimSpace(upid) == "" {
		return "", errors.New("未返回任务号 UPID")
	}
	return upid, nil
}

// ---------- 4. 业务口（SDN 拓扑"物理出口"节点） ----------
//
// 读  : GET  /vapi/json/cluster/network/business-ifaces[?refresh=1]
//       → 扁平数组，元素自带 node_name/node_status，role 含 "business"
// 校验: POST /vapi/json/asan/v1.0/networks/ifacecheck   (JSON)
//       {"host_eth":{hostid:["channel2"]},"net_type":"business_iface","iface":"<uuid>"}
//       → data.is_access_iface
// 写  : POST /vapi/json/hci/sdn/ui/network-portal/nodes/action  (JSON)
//       {"type":"add","nodes":[{"id":"<uuid>","bridge_list":"<JSON 字符串>"}]}
//       → data.task_id
//
// bridge_list 是把"虚拟交换机(evs) → 主机 vlink(channelN)"的映射再序列化成字符串，
// 属于双层 JSON，必须按抓包原样保留字符串形态。

// NetPortalBridge bridge_list 里的单个映射项
type NetPortalBridge struct {
	DeviceType string   `json:"device_type"` // "evs"
	Location   []string `json:"location"`    // [hostid]
	PeerDevice struct {
		VLinkID    string `json:"vlink_id"` // 主机侧聚合口，如 channel2
		DeviceType string `json:"device_type"`
	} `json:"peer_device"`
}

// NewNetPortalBridge 构造一条 evs → host vlink 映射
func NewNetPortalBridge(hostID, vlinkID string) NetPortalBridge {
	var b NetPortalBridge
	b.DeviceType = "evs"
	b.Location = []string{hostID}
	b.PeerDevice.VLinkID = vlinkID
	b.PeerDevice.DeviceType = "host"
	return b
}

// GetBusinessIfaces 查询业务口配置（refresh=true 时强制刷新）
func (c *Client) GetBusinessIfaces(refresh bool) ([]Iface, error) {
	path := "/vapi/json/cluster/network/business-ifaces"
	if refresh {
		path += "?refresh=1"
	}
	return c.getFlatIfaces(path, "业务口")
}

// CheckBusinessIface 业务口接入检查（读-校验-写 中的"校验"）
//
// hostIface: 主机 ID → 该主机的承载口列表（如 {"host-x":["channel2"]}）
func (c *Client) CheckBusinessIface(hostIface map[string][]string, ifaceUUID string) (bool, error) {
	payload := map[string]interface{}{
		"host_eth": hostIface,
		"net_type": "business_iface",
		"iface":    ifaceUUID,
	}
	raw, err := c.callAPIJSON(http.MethodPost, "/vapi/json/asan/v1.0/networks/ifacecheck", payload)
	if err != nil {
		return false, err
	}
	var res struct {
		IsAccessIface bool `json:"is_access_iface"`
	}
	if err := json.Unmarshal(*raw, &res); err != nil {
		return false, fmt.Errorf("解析接入检查结果失败: %w", err)
	}
	return res.IsAccessIface, nil
}

// AddNetworkPortalNodes 创建业务口拓扑节点（写操作）
//
// uuid 由调用方通过 NewUUIDv4() 生成（客户端本地生成，见 NewUUIDv4 注释）。
func (c *Client) AddNetworkPortalNodes(uuid string, bridges []NetPortalBridge) (string, error) {
	if strings.TrimSpace(uuid) == "" {
		return "", errors.New("拓扑节点 ID 为空")
	}
	if len(bridges) == 0 {
		return "", errors.New("未指定任何主机的承载口")
	}
	bridgeJSON, err := json.Marshal(bridges)
	if err != nil {
		return "", fmt.Errorf("序列化 bridge_list 失败: %w", err)
	}
	node := map[string]interface{}{
		"id":          uuid,
		"bridge_list": string(bridgeJSON), // 注意: 内层仍是 JSON 字符串
	}
	payload := map[string]interface{}{
		"type":  "add",
		"nodes": []interface{}{node},
	}
	raw, err := c.callAPIJSON(http.MethodPost, "/vapi/json/hci/sdn/ui/network-portal/nodes/action", payload)
	if err != nil {
		return "", err
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

// ---------- 通用校验与文本工具 ----------

// ValidIPv4 校验是否为合法 IPv4 字面量
func ValidIPv4(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	return ip != nil && ip.To4() != nil
}

// ValidNetmask 校验是否为合法（连续 1 的）IPv4 掩码
func ValidNetmask(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil || ip.To4() == nil {
		return false
	}
	m := ip.To4()
	ones, bits := net.IPMask(m).Size()
	return bits == 32 && ones >= 0
}

// SubnetOf 返回 IP 所在网段（用于快速发现同网段冲突）
func SubnetOf(ipStr, maskStr string) string {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	mask := net.ParseIP(strings.TrimSpace(maskStr))
	if ip == nil || mask == nil || ip.To4() == nil || mask.To4() == nil {
		return ""
	}
	n := net.IPNet{IP: ip.To4().Mask(net.IPMask(mask.To4())), Mask: net.IPMask(mask.To4())}
	return n.String()
}

// SplitLines 把多行文本拆成去空行的切片（IP 列表输入用）
func SplitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// JoinComma 过滤空值后用逗号连接（bond members 用）
func JoinComma(items []string) string {
	var keep []string
	for _, s := range items {
		if t := strings.TrimSpace(s); t != "" {
			keep = append(keep, t)
		}
	}
	return strings.Join(keep, ",")
}
