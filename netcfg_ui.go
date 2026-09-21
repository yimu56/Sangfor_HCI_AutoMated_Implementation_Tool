// netcfg_ui.go: 4 类网络配置页的图形界面
//
//	配置VXLAN的IP   VXLAN IP 池（VXLAN 隧道承载地址）
//	端口聚合        创建聚合口（bond / channelN）
//	配置存储网      存储通信网口
//	配置业务口      业务口（SDN 拓扑"物理出口"节点）
//
// 每个页面统一遵循「读现网 → 选目标 → 预览 diff → 危险确认 → 提交 → 任务跟踪 → 回读验证」，
// 与既有「修改网口配置」页保持同一套交互习惯。
//
// 布局约定（沿用工程既有踩坑结论）:
//   - 不用 GridLayout（walk 下不自动排布），一律 VBox + 每行 HBox
//   - ScrollView 直接当容器，不再包一层 inner
//   - 动态重建控件前必须递归销毁旧句柄（clearChildren）
package main

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/lxn/walk"
)

// ---------- 多选控件组（walk 无 CheckBoxList，用 FlowLayout + CheckBox 自建） ----------

// rowHeight 表单行/工具条的固定高度（像素）
const rowHeight = 26

// checksPerRow 复选框每行大致放几个（用于估算复选框组宽度容量）
const checksPerRow = 5

// reserveRows 复选框区固定预留多少行（**与实际条数无关**）。
//
// 为什么固定而不是按条数算：walk 每次布局都会把窗口撑到"布局最小尺寸"
// （form.go 的 FormBase.startLayout：客户区 < min 就 SetSizePixels），
// 而"按条数算高度"会让最小尺寸跟着数据变化 —— 数据一多（例如某节点有 10 个物理口、
// 复选框排到 3~4 行）窗口就被撑得比屏幕还高，紧接着就出现"最大化后标题栏被吃掉"。
// 固定预留后最小尺寸恒定，窗口尺寸始终可控。实测 2 行即可（标签已压缩，一行能放 6~10 个）。
const reserveRows = 2

// checkGroup 一组带"全选/全不选"的复选框（walk 没有 CheckBoxList，用 FlowLayout + CheckBox 自建）。
//
// 为什么不用 GroupBox 包：实测给 GroupBox 设固定高度会与它自身"标题+边框"的布局冲突，
// 内容被挤到顶部并与标题重叠（6 个节点 2 行时整组不可见）。
// 改成"普通 Composite + 加粗标题行 + 固定总高"，与存储网页每行控件用的是同一套可靠写法。
type checkGroup struct {
	wrap     *walk.Composite
	bar      *walk.Composite
	flow     *walk.Composite
	titleLbl *walk.Label
	countLbl *walk.Label
	pickBtn  *walk.PushButton // 「只选空闲口」（默认隐藏，聚合页启用）
	checks   []*walk.CheckBox
	keys     []string
	freeKeys map[string]bool // 空闲项集合（pickBtn 用）
	onChange func()
}

// newCheckGroup 建一个复选框组（加粗标题 + 计数 + 全选/全不选 + 流式排列的复选框）
func newCheckGroup(parent walk.Container, title string) *checkGroup {
	g := &checkGroup{}

	wrap, _ := walk.NewComposite(parent)
	_ = wrap.SetLayout(walk.NewVBoxLayout())
	g.wrap = wrap

	// 标题行：加粗标题 + 右侧"已选 N / M 项"
	titleRow, _ := walk.NewComposite(wrap)
	_ = titleRow.SetLayout(walk.NewHBoxLayout())
	titleRow.SetMinMaxSize(walk.Size{Height: rowHeight}, walk.Size{Height: rowHeight})
	g.titleLbl, _ = walk.NewLabel(titleRow)
	g.titleLbl.SetText(title)
	if f, err := walk.NewFont("Microsoft YaHei", 9, walk.FontBold); err == nil {
		g.titleLbl.SetFont(f)
	}
	_, _ = walk.NewHSpacer(titleRow)
	g.countLbl, _ = walk.NewLabel(titleRow)
	g.countLbl.SetText("已选 0 项")

	// 工具条
	bar, _ := walk.NewComposite(wrap)
	_ = bar.SetLayout(walk.NewHBoxLayout())
	bar.SetMinMaxSize(walk.Size{Height: rowHeight}, walk.Size{Height: rowHeight})
	g.bar = bar
	allBtn, _ := walk.NewPushButton(bar)
	allBtn.SetText("全选")
	setFixedWidth(allBtn, 76)
	allBtn.Clicked().Attach(func() { g.setAll(true) })
	noneBtn, _ := walk.NewPushButton(bar)
	noneBtn.SetText("全不选")
	setFixedWidth(noneBtn, 76)
	noneBtn.Clicked().Attach(func() { g.setAll(false) })
	// 「只选空闲口」：只勾选"未被任何聚合口/角色占用"的项（聚合页用，避免误把 mgmt 口选进去）
	g.pickBtn, _ = walk.NewPushButton(bar)
	g.pickBtn.SetText("只选空闲口")
	setFixedWidth(g.pickBtn, 110)
	g.pickBtn.SetVisible(false)
	g.pickBtn.Clicked().Attach(func() {
		for i, k := range g.keys {
			if i < len(g.checks) {
				g.checks[i].SetChecked(g.freeKeys[k])
			}
		}
		g.refreshCount()
	})
	_, _ = walk.NewHSpacer(bar)

	// 复选框区
	g.flow, _ = walk.NewComposite(wrap)
	_ = g.flow.SetLayout(walk.NewFlowLayout())
	// 构造时就把预留高度套上：否则"未建/已建"之间会差 100+ DIP，
	// 数据一加载 walk 就把窗口撑高一次（见 reserveRows 注释）
	g.applyReservedHeight()
	return g
}

// applyReservedHeight 把"标题行 + 工具条 + 预留行数的复选框区"高度固定下来（与条数无关）
func (g *checkGroup) applyReservedHeight() {
	if g.flow == nil || g.wrap == nil {
		return
	}
	flowH := reserveRows*rowHeight + (reserveRows-1)*6
	g.flow.SetMinMaxSize(walk.Size{Height: flowH}, walk.Size{Height: flowH})
	total := rowHeight*2 + flowH + 14
	g.wrap.SetMinMaxSize(walk.Size{Height: total}, walk.Size{Height: total})
}

// setTitle 更新加粗标题（成员口候选会随所选节点变化）
func (g *checkGroup) setTitle(title string) {
	if g.titleLbl != nil {
		g.titleLbl.SetText(title)
	}
}

// setFreeKeys 记录"空闲项"集合，供「只选空闲口」按钮使用
func (g *checkGroup) setFreeKeys(free map[string]bool) {
	g.freeKeys = free
}

// enablePickFree 显示「只选空闲口」按钮
func (g *checkGroup) enablePickFree() {
	if g.pickBtn != nil {
		g.pickBtn.SetVisible(true)
	}
}

// rebuild 重建复选框项，并按行数把整组高度固定住
func (g *checkGroup) rebuild(keys, labels []string, checked bool) {
	clearChildren(g.flow)
	g.checks = nil
	g.keys = nil
	for i, k := range keys {
		label := k
		if i < len(labels) && labels[i] != "" {
			label = labels[i]
		}
		cb, err := walk.NewCheckBox(g.flow)
		if err != nil {
			continue
		}
		cb.SetText(label)
		cb.SetChecked(checked)
		cb.CheckedChanged().Attach(g.refreshCount)
		g.checks = append(g.checks, cb)
		g.keys = append(g.keys, k)
	}
	g.refreshCount()

	// 高度固定预留 reserveRows 行（与条数无关，见 reserveRows 注释）
	g.applyReservedHeight()
	g.wrap.RequestLayout()

	// 条数超过容量时在计数里说明一下（避免"看不到的项"被误认为已经不存在）
	if len(g.checks) > reserveRows*checksPerRow && g.countLbl != nil {
		g.countLbl.SetText(fmt.Sprintf("已选 %d / %d 项（最多显示 %d 项）",
			len(g.selected()), len(g.checks), reserveRows*checksPerRow))
	}
}

// refreshCount 刷新"已选 N 项"并回调
func (g *checkGroup) refreshCount() {
	n := len(g.selected())
	if g.countLbl != nil {
		g.countLbl.SetText(fmt.Sprintf("已选 %d / %d 项", n, len(g.checks)))
	}
	if g.onChange != nil {
		g.onChange()
	}
}

// selected 返回勾选项的 key（顺序与重建时一致）
func (g *checkGroup) selected() []string {
	var out []string
	for i, cb := range g.checks {
		if cb.Checked() {
			out = append(out, g.keys[i])
		}
	}
	return out
}

// setAll 全选 / 全不选
func (g *checkGroup) setAll(v bool) {
	for _, cb := range g.checks {
		cb.SetChecked(v)
	}
	g.refreshCount()
}

// setEnabled 整组启用/禁用
func (g *checkGroup) setEnabled(v bool) {
	for _, cb := range g.checks {
		cb.SetEnabled(v)
	}
}

// ---------- 通用小工具 ----------

// clearChildren 递归销毁容器内全部子控件（沿用硬件页刷新修复的做法）
func clearChildren(c walk.Container) {
	if c == nil {
		return
	}
	ch := c.Children()
	for i := ch.Len() - 1; i >= 0; i-- {
		if w := ch.At(i); w != nil {
			disposeWidgetTree(w)
		}
	}
	_ = ch.Clear()
	c.RequestLayout()
}

// cfgDiffRow 一条"字段 / 现值 / 目标值"的差异记录
type cfgDiffRow struct {
	field string
	from  string
	to    string
}

// formatCfgDiff 把差异列表排成等宽对齐表（复用主程序的 dispWidth/padDisp）
func formatCfgDiff(rows []cfgDiffRow) string {
	if len(rows) == 0 {
		return "（无差异）\n"
	}
	w1, w2 := dispWidth("字段"), dispWidth("当前值")
	for _, r := range rows {
		if n := dispWidth(r.field); n > w1 {
			w1 = n
		}
		if n := dispWidth(r.from); n > w2 {
			w2 = n
		}
	}
	var b strings.Builder
	b.WriteString(padDisp("字段", w1) + "  " + padDisp("当前值", w2) + "  " + "目标值\n")
	b.WriteString(strings.Repeat("-", w1+w2+24) + "\n")
	for _, r := range rows {
		b.WriteString(padDisp(r.field, w1) + "  " + padDisp(orDash(r.from), w2) + "  " + r.to + "\n")
	}
	return b.String()
}

// setFixedWidth 固定控件宽度。
// 原因: walk 的 HBoxLayout 会把多余横向空间摊给子控件，导致按钮/输入框被拉得很宽很难看，
// 必须显式给出宽度上下限才能保持"控件按内容宽度、右侧留白"的观感。
func setFixedWidth(w walk.Widget, width int) {
	w.SetMinMaxSize(walk.Size{Width: width, Height: 0}, walk.Size{Width: width, Height: 0})
}

// newDiffText 只读等宽文本框（与"修改网口配置"页一致的外观）
func newDiffText(parent walk.Container, height int) *walk.TextEdit {
	te, _ := walk.NewTextEdit(parent)
	te.SetReadOnly(true)
	if height > 0 {
		// 只给最小高度：作为页面最后一个控件，由它吸收纵向多余空间（避免其它行被拉高）
		te.SetMinMaxSize(walk.Size{Height: height}, walk.Size{})
	}
	if f, err := walk.NewFont("Consolas", 9, 0); err == nil {
		te.SetFont(f)
	}
	return te
}

// mkFormRow 建一行"固定宽标签 + 后续控件放回该行"的容器
func mkFormRow(parent walk.Container, label string, labelWidth int) (*walk.Composite, *walk.Label) {
	row, _ := walk.NewComposite(parent)
	_ = row.SetLayout(walk.NewHBoxLayout())
	// 行高固定，避免 VBox 把多余纵向空间摊到标签行上（表现为一行很高、内容居中悬空）
	row.SetMinMaxSize(walk.Size{Height: rowHeight}, walk.Size{Height: rowHeight})
	lb, _ := walk.NewLabel(row)
	lb.SetText(label)
	lb.SetMinMaxSize(walk.Size{Width: labelWidth, Height: 0}, walk.Size{Width: labelWidth, Height: 0})
	return row, lb
}

// nextIPv4 返回 ip 之后第 n 个地址（用于按节点数自动生成连续 IP）
func nextIPv4(ipStr string, n int) (string, bool) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil || ip.To4() == nil {
		return "", false
	}
	v := ip.To4()
	val := uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
	val += uint32(n)
	out := net.IPv4(byte(val>>24), byte(val>>16), byte(val>>8), byte(val)).To4()
	return out.String(), true
}

// ---------- 现网数据提取辅助 ----------

// bondsOf 从全集群网口里挑出所有聚合口（type=bond）
func bondsOf(groups []NodeIfaces) []ifaceRow {
	var rows []ifaceRow
	for _, g := range groups {
		for _, f := range g.Data {
			if f.Type == "bond" {
				rows = append(rows, ifaceRow{node: g.NodeName, iface: f})
			}
		}
	}
	return rows
}

// ---------- 物理口候选（端口聚合的成员口） ----------

// phyCand 一个物理口候选：附带"是否空闲、被谁占用"的信息。
//
// 注意：不再把"已被聚合口/角色占用的物理口"直接过滤掉——实测现场每节点通常只剩 1 个空闲口
// （且多为 DOWN），所有 UP 口都是 channel1~4 的成员。若只列空闲口，界面上就会出现
// "UP 口全都不见了、只能对 DOWN 口操作"的现象（用户反馈的问题），因此这里改为全部列出、
// 用标签说明占用情况，并在提交确认框里对占用的口单独告警。
type phyCand struct {
	Iface  Iface
	Owner  string // "" = 空闲；"channel2" = 已在某聚合口；"角色 mgmt/vs" = 被角色占用
	LinkUp bool
}

// phyCandidatesOf 返回该节点全部物理口候选（含已被占用的），
// 排序：空闲 UP → 空闲 DOWN → 占用 UP → 占用 DOWN（同类按名称稳定排序）
func phyCandidatesOf(ni NodeIfaces) []phyCand {
	owner := map[string]string{} // 物理口名 -> 所属聚合口名
	for _, f := range ni.Data {
		if f.Type != "bond" {
			continue
		}
		for _, m := range f.Members {
			owner[m] = f.Name
		}
	}
	var out []phyCand
	for _, f := range ni.Data {
		if f.Type != "phy-iface" {
			continue
		}
		c := phyCand{Iface: f, LinkUp: f.Status == 1}
		if own, ok := owner[f.Name]; ok && own != "" {
			c.Owner = own
		} else if len(f.Roles) > 0 {
			c.Owner = "角色 " + strings.Join(f.Roles, "/")
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := phyCandRank(out[i]), phyCandRank(out[j])
		if ri != rj {
			return ri < rj
		}
		return out[i].Iface.Name < out[j].Iface.Name
	})
	return out
}

// phyCandRank 候选排序权重：空闲优先（0/1），其次是链路 UP（0/2）
func phyCandRank(c phyCand) int {
	r := 0
	if c.Owner != "" {
		r += 2
	}
	if !c.LinkUp {
		r++
	}
	return r
}

// freePhyIfacesOf 只取空闲物理口（保留给"需要严格空闲口"的场景）
func freePhyIfacesOf(ni NodeIfaces) []Iface {
	var out []Iface
	for _, c := range phyCandidatesOf(ni) {
		if c.Owner == "" {
			out = append(out, c.Iface)
		}
	}
	return out
}

// bondNamesOf 返回该节点现有聚合口名称（channelN），供存储网/业务口选择承载口
func bondNamesOf(ni NodeIfaces) []string {
	var out []string
	for _, f := range ni.Data {
		if f.Type == "bond" {
			out = append(out, f.Name)
		}
	}
	return out
}

// intersect 取多个字符串切片的交集，保持第一个切片的顺序
func intersect(lists ...[]string) []string {
	if len(lists) == 0 {
		return nil
	}
	var out []string
	for _, s := range lists[0] {
		ok := true
		for _, other := range lists[1:] {
			found := false
			for _, o := range other {
				if o == s {
					found = true
					break
				}
			}
			if !found {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, s)
		}
	}
	return out
}

// groupByHostID 按 hostid 索引网口分组
func groupByHostID(groups []NodeIfaces) map[string]NodeIfaces {
	m := map[string]NodeIfaces{}
	for _, g := range groups {
		m[g.NodeID] = g
	}
	return m
}

// ---------- 页面状态 ----------

// ncResult 后台写操作完成后回报给 UI 的结果
type ncResult struct {
	page string // pool / bond / vs / biz
	msg  string // 任务消息
	note string // 补充说明（回读结果等）
}

type poolLoad struct {
	pools []VXLANIPPool
}

type bondLoad struct {
	groups []NodeIfaces
}

// vsLoad / bizLoad 用 errs 收集"部分接口失败"，避免一个接口异常时整页空白
type vsLoad struct {
	settings []VSNodeSetting
	groups   []NodeIfaces
	errs     []string
}

type bizLoad struct {
	ifaces []Iface
	groups []NodeIfaces
	errs   []string
}

// vsRowCtl 存储网页里"一个节点一行"的控件集合
type vsRowCtl struct {
	hostName string
	hostIP   string // 该节点存储 IP 的现值
	ipEdit   *walk.LineEdit
	maskEdit *walk.LineEdit
	vlanEdit *walk.LineEdit
	nicCombo *walk.ComboBox
	nicVals  []string
}

// netCfgPages 4 个网络配置页的全部控件与状态
type netCfgPages struct {
	app *App

	// ---- 配置VXLAN的IP ----
	poolTable   *walk.TableView
	poolModel   *poolModel
	poolStat    *walk.Label
	poolNodes   *checkGroup
	poolIPs     *walk.TextEdit
	poolMask    *walk.LineEdit
	poolGW      *walk.LineEdit
	poolDesc    *walk.LineEdit
	poolDiff    *walk.TextEdit
	poolPreview *walk.PushButton
	poolSubmit  *walk.PushButton
	poolCur     []VXLANIPPool

	// ---- 端口聚合 ----
	bondTable   *walk.TableView
	bondModel   *bondModel
	bondStat    *walk.Label
	bondNodes   *checkGroup
	bondMembers *checkGroup
	bondMode    *walk.ComboBox
	bondFusion  *walk.CheckBox
	bondDiff    *walk.TextEdit
	bondPreview *walk.PushButton
	bondSubmit  *walk.PushButton
	bondGroups  []NodeIfaces

	// ---- 配置存储网 ----
	vsTable    *walk.TableView
	vsModel    *vsModel
	vsStat     *walk.Label
	vsScroll   *walk.ScrollView
	vsStartIP  *walk.LineEdit
	vsFillBtn  *walk.PushButton
	vsDiff     *walk.TextEdit
	vsPreview  *walk.PushButton
	vsSubmit   *walk.PushButton
	vsSettings []VSNodeSetting
	vsGroups   []NodeIfaces
	vsRows     []*vsRowCtl

	// ---- 配置业务口 ----
	bizTable   *walk.TableView
	bizModel   *bizModel
	bizStat    *walk.Label
	bizNodes   *checkGroup
	bizVLink   *walk.ComboBox
	bizUUID    *walk.LineEdit
	bizRegen   *walk.PushButton
	bizDiff    *walk.TextEdit
	bizPreview *walk.PushButton
	bizSubmit  *walk.PushButton
	bizIfaces  []Iface
	bizGroups  []NodeIfaces
}

// ---------- 表格模型 ----------

// poolModel VXLAN IP 池现状表
type poolModel struct {
	walk.TableModelBase
	items []VXLANIPPool
}

func (m *poolModel) RowCount() int { return len(m.items) }

func (m *poolModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(m.items) {
		return ""
	}
	p := m.items[row]
	switch col {
	case 0:
		return truncate(p.ID, 14)
	case 1:
		if len(p.IPRange) > 0 {
			return p.IPRange[0]
		}
		return "-"
	case 2:
		return orDash(p.Netmask)
	case 3:
		return derefStr(p.Gateway)
	case 4:
		return len(p.IPRange)
	case 5:
		return len(p.NodeIPs)
	case 6:
		return p.LeftIPNumber
	case 7:
		return orDash(p.Description)
	}
	return ""
}

// bondModel 聚合口现状表（含所属节点）
type bondModel struct {
	walk.TableModelBase
	items []ifaceRow
}

func (m *bondModel) RowCount() int { return len(m.items) }

func (m *bondModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(m.items) {
		return ""
	}
	r := m.items[row]
	f := r.iface
	switch col {
	case 0:
		return r.node
	case 1:
		return f.Name
	case 2:
		return orDash(f.Mode)
	case 3:
		return membersText(&f)
	case 4:
		return ifaceStatus(f.Status)
	case 5:
		return speedText(f.Speed.Value, f.Speed.Duplex)
	case 6:
		return rolesText(f.Roles)
	case 7:
		return ifaceRemark(f)
	}
	return ""
}

// vsModel 存储网现状表
type vsModel struct {
	walk.TableModelBase
	items []VSNodeSetting
}

func (m *vsModel) RowCount() int { return len(m.items) }

func (m *vsModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(m.items) {
		return ""
	}
	s := m.items[row]
	switch col {
	case 0:
		return orDash(s.HostAlias)
	case 1:
		return truncate(s.HostName, 22)
	case 2:
		return orDash(s.HostIP)
	case 3:
		return orDash(s.Netmask)
	case 4:
		return orDash(strings.Join(s.Nics, ","))
	case 5:
		return s.VLANID
	case 6:
		return orDash(s.Type)
	case 7:
		if s.HostStatus == 1 {
			return "在线"
		}
		return "离线"
	}
	return ""
}

// bizModel 业务口现状表
type bizModel struct {
	walk.TableModelBase
	items []Iface
}

func (m *bizModel) RowCount() int { return len(m.items) }

func (m *bizModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(m.items) {
		return ""
	}
	f := m.items[row]
	switch col {
	case 0:
		return ifaceNodeText(f)
	case 1:
		return f.Name
	case 2:
		return orDash(f.Type)
	case 3:
		return orDash(f.Mode)
	case 4:
		return membersText(&f)
	case 5:
		return ifaceStatus(f.Status)
	case 6:
		return rolesText(f.Roles)
	}
	return ""
}
