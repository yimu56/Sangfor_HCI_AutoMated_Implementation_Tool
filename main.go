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
//   - 登录成功后自动刷新 节点/网口/虚拟机/硬件/网络配置 数据
//   - 修改网口配置页面: 选择节点 -> 选择网口 -> 修改字段 -> 预览变更 -> 确认提交
//   - 修改网口跳过密码二次校验（VerifyPassword），直接提交，后续人工验证
//   - 会话与上次输入默认值缓存在可执行文件同目录（.sangfor-session.json / .sangfor-lastinput.json）
//
// 网络配置页（4 类写操作，协议见 netcfg.go，界面见 netcfg_ui.go / netcfg_pages.go）:
//
//	VXLAN IP 池   读 GET  /vapi/extjs/network/v1.0/vxlan-ip-pools?start=0&limit=20
//	              写 POST /vapi/extjs/network/v1.0/vxlan-ip-pools            (JSON)
//	端口聚合      写 POST /vapi/json/cluster/network/bonds                 (form)
//	              读: 无独立接口，取 /cluster/network/ifaces 中 type=bond 的元素
//	存储网        读 GET  /vapi/extjs/vs/vs_config/vs_networksetting_get?add_host=0
//	              验 POST /vapi/json/vs/vs_config/vs_check_arbiter_same_netip (form)
//	              写 POST /vapi/extjs/vs/vs_config/vs_networksetting_set      (form)
//	                 → data 直接是 UPID 字符串（不是 task_id 字段）
//	              回读 GET /vapi/extjs/vs/vs_config/is_net_config → type: NONE → standard_network
//	业务口        读 GET  /vapi/json/cluster/network/business-ifaces[?refresh=1]
//	              验 POST /vapi/json/asan/v1.0/networks/ifacecheck           (JSON)
//	              写 POST /vapi/json/hci/sdn/ui/network-portal/nodes/action   (JSON)
//	                 bridge_list 是"内层 JSON 字符串"，拓扑节点 ID 由客户端生成 UUIDv4
//
// 历史命令行版保留在 main_cli_backup.go，需要可自行取回。

package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	a, err := newApp()
	if err != nil {
		fmt.Fprintln(os.Stderr, "初始化界面失败:", err)
		os.Exit(1)
	}
	a.Show()
	// 窗口显示后再定尺寸/位置：此时才有真实 DPI 与非客户区高度可算。
	//
	// 目标尺寸的取法：
	//   宽度 1240 DIP —— 够放下 10 个页签（页签被折叠就没有入口了）；
	//   高度 560 DIP —— **故意小于布局的最小高度**：walk 会把窗口收敛到"布局最小尺寸"
	//     （实测 2480x1359 客户区），这个尺寸正好装得下内容、又不会比屏幕还高。
	//     窗口一旦高过屏幕，Windows 最大化时会把客户区扩成整窗、标题栏（最小化/最大化/关闭）
	//     被内容盖住 —— 这正是本次要修的问题，所以不能让窗口"越高越好"。
	applyWindowGeometry(a.MainWindow, 1240, 560)
	// walk 会在 Run() 里再按"布局最小尺寸"把窗口撑大一次（form.go: Run → SetBoundsPixels），
	// 且布局最小尺寸会随数据（复选框行数）变化，所以 Run() 之后再幂等收敛几次。
	// 用 Synchronize 保证在 UI 线程执行。
	for _, d := range []time.Duration{300 * time.Millisecond, 900 * time.Millisecond,
		1800 * time.Millisecond} {
		time.AfterFunc(d, func() {
			a.Synchronize(func() { applyWindowGeometry(a.MainWindow, 1240, 560) })
		})
	}
	a.Run()
}
