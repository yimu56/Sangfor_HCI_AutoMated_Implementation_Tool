// netcfg_pages.go: 4 个网络配置页的页面搭建与业务逻辑
//
// 提交策略（两阶段，沿用"修改网口配置"页的保护级别并加强）:
//
//	第一阶段 读现网 + 本地校验（IP/掩码合法性、数量匹配）
//	第二阶段 设备侧预校验（存储网 vs_check_arbiter_same_netip / 业务口 ifacecheck）
//	→ 把「现网值 vs 目标值」差异 + 预校验告警一起放进危险确认框
//	→ 用户点"是"后才真正下发，下发后轮询任务并回读现网确认
package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lxn/walk"
)

// ---------- 页面搭建 ----------

// buildNetCfgPages 创建 4 个配置页并挂到 notebook 上
func buildNetCfgPages(a *App, nb *walk.TabWidget) (*netCfgPages, error) {
	p := &netCfgPages{app: a}

	pages := []struct {
		title string
		build func(*walk.TabWidget) (*walk.TabPage, error)
	}{
		{"配置VXLAN的IP", p.buildPoolPage},
		{"端口聚合", p.buildBondPage},
		{"配置存储网", p.buildVSPage},
		{"配置业务口", p.buildBizPage},
	}
	for _, it := range pages {
		page, err := it.build(nb)
		if err != nil {
			return nil, err
		}
		_ = page.SetTitle(it.title)
		nb.Pages().Add(page)
	}

	// 业务口拓扑节点 ID：默认就用本地生成的 UUIDv4
	if p.bizUUID != nil {
		p.bizUUID.SetText(NewUUIDv4())
	}
	return p, nil
}

// newPageBar 页面顶部工具条：[刷新] + 状态标签 + 右侧 [复制现状]
func newPageBar(page *walk.TabPage, refresh func(), stat **walk.Label, hint string, copyFn func()) {
	bar, _ := walk.NewComposite(page)
	_ = bar.SetLayout(walk.NewHBoxLayout())

	btn, _ := walk.NewPushButton(bar)
	btn.SetText("刷新现网配置")
	btn.Clicked().Attach(refresh)

	lbl, _ := walk.NewLabel(bar)
	lbl.SetText(hint)
	*stat = lbl
	if copyFn != nil {
		_, _ = walk.NewHSpacer(bar)
		cp, _ := walk.NewPushButton(bar)
		cp.SetText("复制现状")
		cp.Clicked().Attach(copyFn)
	}
}

// pageBody 页面主体：上=现网表格（固定高度），下=编辑区（占据剩余空间）。
//
// 不用 VSplitter 的原因（实测）：分割条默认 50/50，当"现网表格只有几行"而
// "编辑区需要按节点数放多行控件"时，编辑区会被压得很矮（存储网页的每节点编辑行
// 直接被挤出可视区）。改为显式固定上侧高度，编辑区高度可预期。
func pageBody(page *walk.TabPage, topHeight int) (*walk.GroupBox, *walk.GroupBox) {
	top, _ := walk.NewGroupBox(page)
	_ = top.SetLayout(walk.NewVBoxLayout())
	top.SetMinMaxSize(walk.Size{Height: topHeight}, walk.Size{Height: topHeight})
	bottom, _ := walk.NewGroupBox(page)
	_ = bottom.SetLayout(walk.NewVBoxLayout())
	return top, bottom
}

// ---------- 页 1: 配置VXLAN的IP ----------

func (p *netCfgPages) buildPoolPage(nb *walk.TabWidget) (*walk.TabPage, error) {
	page, _ := walk.NewTabPage()
	if err := page.SetLayout(walk.NewVBoxLayout()); err != nil {
		return nil, err
	}
	newPageBar(page, func() { go p.fetchPools() }, &p.poolStat,
		"点击「刷新现网配置」读取设备上已有的 VXLAN IP 池", p.copyPoolState)

	top, bottom := pageBody(page, 110)
	_ = top.SetTitle("当前 VXLAN IP 池（现网）")
	p.poolTable, _ = walk.NewTableView(top)
	p.poolModel = &poolModel{}
	p.poolTable.SetModel(p.poolModel)
	addCol(p.poolTable, "池 ID", 130)
	addCol(p.poolTable, "首个 IP", 130)
	addCol(p.poolTable, "掩码", 130)
	addCol(p.poolTable, "网关", 120)
	addCol(p.poolTable, "IP 数", 60)
	addCol(p.poolTable, "已分配节点", 90)
	addCol(p.poolTable, "剩余", 60)
	addCol(p.poolTable, "描述", 140)
	p.poolTable.SetColumnsOrderable(true)
	p.poolTable.SetLastColumnStretched(true)

	_ = bottom.SetTitle("下发新的 VXLAN IP 池（危险写操作）")
	p.poolNodes = newCheckGroup(bottom, "目标节点（IP 按勾选顺序一一分配给节点）")

	row, _ := mkFormRow(bottom, "IP 列表:", 90)
	lbl, _ := walk.NewLabel(row)
	lbl.SetText("每行一个 IP，数量需等于选中节点数")
	p.poolIPs, _ = walk.NewTextEdit(bottom)
	p.poolIPs.SetMinMaxSize(walk.Size{Height: 64}, walk.Size{Height: 64})

	row2, _ := mkFormRow(bottom, "掩码:", 90)
	p.poolMask, _ = walk.NewLineEdit(row2)
	p.poolMask.SetText("255.255.255.0")
	setFixedWidth(p.poolMask, 140)
	lbGW, _ := walk.NewLabel(row2)
	lbGW.SetText("  网关:")
	p.poolGW, _ = walk.NewLineEdit(row2)
	setFixedWidth(p.poolGW, 140)
	lbDesc, _ := walk.NewLabel(row2)
	lbDesc.SetText("  描述:")
	p.poolDesc, _ = walk.NewLineEdit(row2)
	setFixedWidth(p.poolDesc, 200)
	_, _ = walk.NewHSpacer(row2)

	btnBar, _ := walk.NewComposite(bottom)
	_ = btnBar.SetLayout(walk.NewHBoxLayout())
	fillBtn, _ := walk.NewPushButton(btnBar)
	fillBtn.SetText("按节点数生成连续 IP")
	setFixedWidth(fillBtn, 170)
	fillBtn.Clicked().Attach(p.onPoolAutoFill)
	p.poolPreview, _ = walk.NewPushButton(btnBar)
	p.poolPreview.SetText("预览变更")
	setFixedWidth(p.poolPreview, 110)
	p.poolPreview.Clicked().Attach(p.onPoolPreview)
	p.poolSubmit, _ = walk.NewPushButton(btnBar)
	p.poolSubmit.SetText("提交下发")
	setFixedWidth(p.poolSubmit, 110)
	p.poolSubmit.Clicked().Attach(p.onPoolSubmit)
	_, _ = walk.NewHSpacer(btnBar)
	hint, _ := walk.NewLabel(btnBar)
	hint.SetText("⚠ 会覆盖/新增 VXLAN 承载地址池，务必先核对")

	p.poolDiff = newDiffText(bottom, 68)
	return page, nil
}

// onPoolAutoFill 用第一个 IP + 选中节点数，自动生成连续 IP 填充到列表
func (p *netCfgPages) onPoolAutoFill() {
	lines := SplitLines(p.poolIPs.Text())
	n := len(p.poolNodes.selected())
	if len(lines) == 0 {
		walk.MsgBox(p.app, "提示", "请先在 IP 列表里填写第一个 IP。", walk.MsgBoxIconInformation)
		return
	}
	if n == 0 {
		walk.MsgBox(p.app, "提示", "请先勾选目标节点。", walk.MsgBoxIconInformation)
		return
	}
	first := lines[0]
	var out []string
	for i := 0; i < n; i++ {
		ip, ok := nextIPv4(first, i)
		if !ok {
			walk.MsgBox(p.app, "提示", "起始 IP 不合法: "+first, walk.MsgBoxIconError)
			return
		}
		out = append(out, ip)
	}
	p.poolIPs.SetText(strings.Join(out, "\r\n"))
	p.setPoolStat(fmt.Sprintf("已按 %d 个节点生成 %d 个连续 IP", n, n))
}

// collectPoolInput 收集并校验 IP 池输入
func (p *netCfgPages) collectPoolInput() (ips []string, mask, gw, desc string, nodeIDs []string, err error) {
	ips = SplitLines(p.poolIPs.Text())
	nodeIDs = p.poolNodes.selected()
	mask = strings.TrimSpace(p.poolMask.Text())
	gw = strings.TrimSpace(p.poolGW.Text())
	desc = strings.TrimSpace(p.poolDesc.Text())

	if len(nodeIDs) == 0 {
		return nil, "", "", "", nil, fmt.Errorf("请至少勾选一个目标节点")
	}
	if len(ips) == 0 {
		return nil, "", "", "", nil, fmt.Errorf("IP 列表为空")
	}
	if len(ips) != len(nodeIDs) {
		return nil, "", "", "", nil, fmt.Errorf("IP 数量(%d)与节点数量(%d)不一致", len(ips), len(nodeIDs))
	}
	for i, ip := range ips {
		if !ValidIPv4(ip) {
			return nil, "", "", "", nil, fmt.Errorf("第 %d 个 IP 不合法: %s", i+1, ip)
		}
	}
	seen := map[string]int{}
	for i, ip := range ips {
		if j, ok := seen[ip]; ok {
			return nil, "", "", "", nil, fmt.Errorf("IP 重复: %s（第 %d 与第 %d 项）", ip, j+1, i+1)
		}
		seen[ip] = i
	}
	if !ValidNetmask(mask) {
		return nil, "", "", "", nil, fmt.Errorf("掩码不合法: %s", mask)
	}
	if gw != "" {
		if !ValidIPv4(gw) {
			return nil, "", "", "", nil, fmt.Errorf("网关不合法: %s", gw)
		}
		if SubnetOf(gw, mask) != SubnetOf(ips[0], mask) {
			return nil, "", "", "", nil, fmt.Errorf("网关 %s 与 IP 段 %s 不在同一网段", gw, SubnetOf(ips[0], mask))
		}
	}
	return ips, mask, gw, desc, nodeIDs, nil
}

// poolPlanText 生成目标分配方案文本（IP ↔ 节点按顺序对应）
func (p *netCfgPages) poolPlanText(ips []string, nodeIDs []string) string {
	var b strings.Builder
	for i, id := range nodeIDs {
		b.WriteString(fmt.Sprintf("  %-24s → %s\n", p.nodeLabel(id), ips[i]))
	}
	return b.String()
}

func (p *netCfgPages) onPoolPreview() {
	ips, mask, gw, desc, nodeIDs, err := p.collectPoolInput()
	if err != nil {
		walk.MsgBox(p.app, "参数有误", err.Error(), walk.MsgBoxIconError)
		return
	}
	var b strings.Builder
	b.WriteString("目标 VXLAN IP 池:\n")
	b.WriteString(fmt.Sprintf("  掩码: %s   网关: %s   描述: %s   IP 数: %d\n\n", mask, orDash(gw), orDash(desc), len(ips)))
	b.WriteString("节点分配方案（按勾选顺序）:\n")
	b.WriteString(p.poolPlanText(ips, nodeIDs))
	if len(p.poolCur) > 0 {
		b.WriteString(fmt.Sprintf("\n设备上现有 IP 池 %d 个，本次为【新增】一个池，不会删除已有池。\n", len(p.poolCur)))
	} else {
		b.WriteString("\n设备上当前没有任何 VXLAN IP 池，本次为首次创建。\n")
	}
	b.WriteString("\n⚠ 此操作会改变 VXLAN 隧道承载地址，可能导致跨主机通信中断！")
	p.poolDiff.SetText(b.String())
	p.setPoolStat("已生成预览")
}

func (p *netCfgPages) onPoolSubmit() {
	a := p.app
	if a.client == nil {
		walk.MsgBox(a, "提示", "请先登录设备。", walk.MsgBoxIconInformation)
		return
	}
	ips, mask, gw, desc, nodeIDs, err := p.collectPoolInput()
	if err != nil {
		walk.MsgBox(a, "参数有误", err.Error(), walk.MsgBoxIconError)
		return
	}
	var b strings.Builder
	b.WriteString("即将向设备下发新的 VXLAN IP 池:\n\n")
	b.WriteString(fmt.Sprintf("掩码: %s   网关: %s   描述: %s\n\n", mask, orDash(gw), orDash(desc)))
	b.WriteString("节点分配方案:\n")
	b.WriteString(p.poolPlanText(ips, nodeIDs))
	b.WriteString("\n⚠ 此操作非常危险，可能导致 VXLAN 隧道承载地址变化、跨主机通信中断！\n")
	b.WriteString("确认执行请点击 [是]，点击 [否] 取消。")
	p.poolDiff.SetText(b.String())

	if ret := walk.MsgBox(a, "危险操作确认", b.String(), walk.MsgBoxYesNo|walk.MsgBoxIconWarning); ret != walk.DlgCmdYes {
		return
	}

	p.poolSubmit.SetEnabled(false)
	p.poolPreview.SetEnabled(false)
	p.poolSubmit.SetText("执行中...")
	p.setPoolStat("正在下发 VXLAN IP 池...")
	client := a.client
	go func() {
		pool, err := client.CreateVXLANIPPool(ips, mask, gw, nodeIDs, desc)
		if err != nil {
			a.post("nc_task_done", err, ncResult{page: "pool"})
			return
		}
		var sb strings.Builder
		sb.WriteString("池 ID: " + pool.ID + "\n")
		sb.WriteString(fmt.Sprintf("掩码: %s   IP 数: %d   剩余可用: %d\n", pool.Netmask, len(pool.IPRange), pool.LeftIPNumber))
		sb.WriteString("设备返回的节点分配结果:\n")
		for _, line := range DescribeNodeIPMap(pool, func(id string) string { return id }) {
			sb.WriteString("  " + line + "\n")
		}
		a.post("nc_task_done", nil, ncResult{page: "pool", msg: "VXLAN IP 池下发成功", note: sb.String()})
	}()
}

func (p *netCfgPages) copyPoolState() {
	if len(p.poolCur) == 0 {
		walk.MsgBox(p.app, "无数据", "当前没有 VXLAN IP 池数据，请先刷新。", walk.MsgBoxIconInformation)
		return
	}
	var b strings.Builder
	b.WriteString("VXLAN IP 池:\n")
	for _, pool := range p.poolCur {
		b.WriteString(fmt.Sprintf("池 %s  掩码 %s  网关 %s  剩余 %d\n",
			pool.ID, pool.Netmask, derefStr(pool.Gateway), pool.LeftIPNumber))
		b.WriteString("  IP 列表: " + strings.Join(pool.IPRange, ", ") + "\n")
		for _, ni := range pool.NodeIPs {
			b.WriteString(fmt.Sprintf("  %s -> %s\n", p.nodeLabel(ni.NodeID), ni.VXLANIP))
		}
	}
	_ = walk.Clipboard().SetText(b.String())
	walk.MsgBox(p.app, "已复制", "VXLAN IP 池信息已复制到剪贴板。", walk.MsgBoxIconInformation)
}

// ---------- 页 2: 端口聚合 ----------

func (p *netCfgPages) buildBondPage(nb *walk.TabWidget) (*walk.TabPage, error) {
	page, _ := walk.NewTabPage()
	if err := page.SetLayout(walk.NewVBoxLayout()); err != nil {
		return nil, err
	}
	newPageBar(page, func() { go p.fetchBonds() }, &p.bondStat,
		"点击「刷新现网配置」读取各节点已有聚合口与空闲物理口", p.copyBondState)

	top, bottom := pageBody(page, 120)
	_ = top.SetTitle("当前聚合口（现网，来自 /cluster/network/ifaces 中 type=bond）")
	p.bondTable, _ = walk.NewTableView(top)
	p.bondModel = &bondModel{}
	p.bondTable.SetModel(p.bondModel)
	addCol(p.bondTable, "节点", 120)
	addCol(p.bondTable, "聚合口", 90)
	addCol(p.bondTable, "聚合模式", 120)
	addCol(p.bondTable, "成员口", 130)
	addCol(p.bondTable, "状态", 60)
	addCol(p.bondTable, "速率", 110)
	addCol(p.bondTable, "角色", 110)
	addCol(p.bondTable, "备注", 140)
	p.bondTable.SetColumnsOrderable(true)
	p.bondTable.SetLastColumnStretched(true)

	_ = bottom.SetTitle("创建聚合口（危险写操作）")
	p.bondNodes = newCheckGroup(bottom, "目标节点")
	p.bondNodes.onChange = p.refreshBondMembers
	p.bondMembers = newCheckGroup(bottom, "成员口（所选节点共有的空闲物理口）")

	row, _ := mkFormRow(bottom, "聚合模式:", 90)
	p.bondMode, _ = walk.NewComboBox(row)
	setFixedWidth(p.bondMode, 190)
	lb, _ := walk.NewLabel(row)
	lb.SetText("（lacp-layer34 为抓包实测值，可直接手输其它模式）")
	_, _ = walk.NewHSpacer(row)
	p.bondFusion, _ = walk.NewCheckBox(row)
	p.bondFusion.SetText("启用融合(fusion)")

	btnBar, _ := walk.NewComposite(bottom)
	_ = btnBar.SetLayout(walk.NewHBoxLayout())
	p.bondPreview, _ = walk.NewPushButton(btnBar)
	p.bondPreview.SetText("预览变更")
	setFixedWidth(p.bondPreview, 110)
	p.bondPreview.Clicked().Attach(p.onBondPreview)
	p.bondSubmit, _ = walk.NewPushButton(btnBar)
	p.bondSubmit.SetText("提交创建")
	setFixedWidth(p.bondSubmit, 110)
	p.bondSubmit.Clicked().Attach(p.onBondSubmit)
	_, _ = walk.NewHSpacer(btnBar)
	hint, _ := walk.NewLabel(btnBar)
	hint.SetText("⚠ 重建聚合口会短暂中断该口链路；成员口可选空闲口，也可选已被 channel1~4 占用的口（提交前会再次告警）")

	p.bondDiff = newDiffText(bottom, 60)
	return page, nil
}

// refreshBondMembers 按当前勾选节点，重建成员口候选（取各节点物理口的交集）。
//
// 候选范围 = 该节点【全部】物理口，而不是只保留空闲口。原因（用户实测反馈）：
// 现场每节点往往只剩 1 个空闲物理口、且多为 DOWN（比如 eth0），而所有 UP 口都是
// channel1~4 的成员 —— 如果只列空闲口，界面上就会出现"UP 口的接口全都不显示、
// 只能对 DOWN 口做聚合"的现象，而用户真正想聚合的恰恰是有连线的 UP 口。
//
// 现在：全部列出 + 标注"链路状态/占用者"，空闲与 UP 排在前面，已占用的可勾选但在
// 提交确认框里会单独告警；另提供「只选空闲口」按钮便于保守操作。
func (p *netCfgPages) refreshBondMembers() {
	ids := p.bondNodes.selected()
	if len(ids) == 0 {
		p.bondMembers.setFreeKeys(nil)
		p.bondMembers.rebuild(nil, nil, true)
		return
	}
	byID := groupByHostID(p.bondGroups)
	var sets [][]string
	detail := map[string]phyCand{} // 名称 -> 详情（优先取"更空闲"的节点）
	for _, id := range ids {
		ni, ok := byID[id]
		if !ok {
			continue
		}
		var names []string
		for _, c := range phyCandidatesOf(ni) {
			names = append(names, c.Iface.Name)
			if prev, dup := detail[c.Iface.Name]; !dup || (prev.Owner != "" && c.Owner == "") {
				detail[c.Iface.Name] = c
			}
		}
		sets = append(sets, names)
	}
	if len(sets) == 0 {
		p.bondMembers.setFreeKeys(nil)
		p.bondMembers.rebuild(nil, nil, true)
		return
	}
	common := intersect(sets...)
	// 空闲优先、UP 优先（便于"想用 UP 口"的用户第一眼看到）
	sort.SliceStable(common, func(i, j int) bool {
		ri, rj := phyCandRank(detail[common[i]]), phyCandRank(detail[common[j]])
		if ri != rj {
			return ri < rj
		}
		return common[i] < common[j]
	})

	free := map[string]bool{}
	nFree, nUp := 0, 0
	labels := make([]string, 0, len(common))
	for _, name := range common {
		c := detail[name]
		state := "DOWN"
		if c.LinkUp {
			state = "UP"
			nUp++
		}
		occ := "空闲"
		if c.Owner != "" {
			if strings.HasPrefix(c.Owner, "角色") {
				occ = c.Owner
			} else {
				occ = "属" + c.Owner
			}
		} else {
			free[name] = true
			nFree++
		}
		// 标签尽量短（复选框一行能放下更多）：网口名 + UP/DOWN + 速率（DOWN 口不显示）+ 占用情况
		if sp := shortSpeed(c.Iface.Speed.Value); sp != "" {
			labels = append(labels, fmt.Sprintf("%s %s %s %s", name, state, sp, occ))
		} else {
			labels = append(labels, fmt.Sprintf("%s %s %s", name, state, occ))
		}
	}
	p.bondMembers.setFreeKeys(free)
	p.bondMembers.enablePickFree()
	p.bondMembers.setTitle(fmt.Sprintf(
		"成员口（所选 %d 个节点共有的 %d 个物理口：空闲 %d，已被占用 %d，其中 UP %d；各节点端口不一致时请分开配置）",
		len(ids), len(common), nFree, len(common)-nFree, nUp))
	p.bondMembers.rebuild(common, labels, false)
}

// bondOccupyWarning 检查所选成员口里有没有"已被占用"的口（依据最近一次刷新的现网数据），
// 返回告警文案（没有则返回空串）。这些口提交后可能被移出原聚合口/角色，风险必须显式提示。
func (p *netCfgPages) bondOccupyWarning(members []string) string {
	want := map[string]bool{}
	for _, m := range members {
		want[m] = true
	}
	owners := map[string]map[string]bool{} // 物理口 -> 占用者集合
	for _, ni := range p.bondGroups {
		for _, c := range phyCandidatesOf(ni) {
			if c.Owner == "" || !want[c.Iface.Name] {
				continue
			}
			if owners[c.Iface.Name] == nil {
				owners[c.Iface.Name] = map[string]bool{}
			}
			owners[c.Iface.Name][c.Owner] = true
		}
	}
	if len(owners) == 0 {
		return ""
	}
	names := make([]string, 0, len(owners))
	for n := range owners {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("\n⚠ 以下成员口当前并非空闲（以上次刷新的现网数据为准），提交后可能被移出\n")
	b.WriteString("  原有聚合口或角色，导致对应链路 / 管理网络 / 存储网络 / 业务网络中断：\n")
	for _, n := range names {
		var os []string
		for o := range owners[n] {
			os = append(os, o)
		}
		sort.Strings(os)
		b.WriteString(fmt.Sprintf("    %-8s %s\n", n, strings.Join(os, "、")))
	}
	return b.String()
}

// shortSpeed 把速率压缩成短标签（10G / 1G / 100M / -），用于复选框这类空间紧张的地方
func shortSpeed(v int) string {
	switch {
	case v >= 1000:
		return fmt.Sprintf("%dG", v/1000)
	case v > 0:
		return fmt.Sprintf("%dM", v)
	}
	return ""
}

// membersOf 从规格里取出成员口列表（成员口在所有节点上一致）
func membersOf(specs []BondSpec) []string {
	if len(specs) == 0 {
		return nil
	}
	var out []string
	for _, m := range strings.Split(specs[0].Members, ",") {
		if m = strings.TrimSpace(m); m != "" {
			out = append(out, m)
		}
	}
	return out
}

// collectBondSpecs 收集并校验聚合口参数
func (p *netCfgPages) collectBondSpecs() ([]BondSpec, error) {
	nodeIDs := p.bondNodes.selected()
	members := p.bondMembers.selected()
	mode := strings.TrimSpace(p.bondMode.Text())
	if len(nodeIDs) == 0 {
		return nil, fmt.Errorf("请至少勾选一个目标节点")
	}
	if len(members) == 0 {
		return nil, fmt.Errorf("请至少选择一个成员口")
	}
	if mode == "" {
		return nil, fmt.Errorf("请选择或填写聚合模式")
	}
	fusion := 0
	if p.bondFusion.Checked() {
		fusion = 1
	}
	var specs []BondSpec
	for _, id := range nodeIDs {
		specs = append(specs, BondSpec{
			NodeID:       id,
			Members:      JoinComma(members),
			Mode:         mode,
			FusionEnable: fusion,
		})
	}
	return specs, nil
}

func (p *netCfgPages) onBondPreview() {
	specs, err := p.collectBondSpecs()
	if err != nil {
		walk.MsgBox(p.app, "参数有误", err.Error(), walk.MsgBoxIconError)
		return
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("将为以下 %d 个节点创建聚合口:\n\n", len(specs)))
	for _, s := range specs {
		b.WriteString(fmt.Sprintf("  %-24s 成员口 %-16s 模式 %s\n", p.nodeLabel(s.NodeID), s.Members, s.Mode))
	}
	if rows := bondsOf(p.bondGroups); len(rows) > 0 {
		b.WriteString(fmt.Sprintf("\n设备上现有聚合口 %d 个：\n", len(rows)))
		for _, r := range rows {
			b.WriteString(fmt.Sprintf("  %-20s %-10s %-14s %s\n",
				r.node, r.iface.Name, orDash(r.iface.Mode), membersText(&r.iface)))
		}
	}
	b.WriteString("\n⚠ 此操作会重建/新增聚合口，相关链路会短暂中断！")
	b.WriteString(p.bondOccupyWarning(membersOf(specs)))
	p.bondDiff.SetText(b.String())
	p.setBondStat("已生成预览")
}

func (p *netCfgPages) onBondSubmit() {
	a := p.app
	if a.client == nil {
		walk.MsgBox(a, "提示", "请先登录设备。", walk.MsgBoxIconInformation)
		return
	}
	specs, err := p.collectBondSpecs()
	if err != nil {
		walk.MsgBox(a, "参数有误", err.Error(), walk.MsgBoxIconError)
		return
	}
	var b strings.Builder
	b.WriteString("即将创建聚合口:\n\n")
	for _, s := range specs {
		b.WriteString(fmt.Sprintf("节点 %s\n  成员口: %s\n  聚合模式: %s\n  融合: %d\n",
			p.nodeLabel(s.NodeID), s.Members, s.Mode, s.FusionEnable))
	}
	b.WriteString(p.bondOccupyWarning(membersOf(specs)))
	b.WriteString("\n⚠ 此操作非常危险，可能导致网络中断或不可逆的配置变更！\n")
	b.WriteString("确认执行请点击 [是]，点击 [否] 取消。")
	p.bondDiff.SetText(b.String())

	if ret := walk.MsgBox(a, "危险操作确认", b.String(), walk.MsgBoxYesNo|walk.MsgBoxIconWarning); ret != walk.DlgCmdYes {
		return
	}

	p.bondSubmit.SetEnabled(false)
	p.bondPreview.SetEnabled(false)
	p.bondSubmit.SetText("执行中...")
	p.setBondStat("正在创建聚合口...")
	client := a.client
	go func() {
		taskID, err := client.CreateBonds(specs)
		if err != nil {
			a.post("nc_task_done", err, ncResult{page: "bond"})
			return
		}
		msg, err := client.WaitTask(taskID, 3*time.Minute)
		if err != nil {
			a.post("nc_task_done", err, ncResult{page: "bond", msg: msg})
			return
		}
		a.post("nc_task_done", nil, ncResult{page: "bond", msg: "聚合口创建任务执行完成", note: orDash(msg)})
	}()
}

func (p *netCfgPages) copyBondState() {
	rows := bondsOf(p.bondGroups)
	if len(rows) == 0 {
		walk.MsgBox(p.app, "无数据", "当前没有聚合口数据，请先刷新。", walk.MsgBoxIconInformation)
		return
	}
	var b strings.Builder
	b.WriteString("聚合口现状:\n")
	for _, r := range rows {
		b.WriteString(fmt.Sprintf("%-20s %-10s %-14s 成员 %s\n",
			r.node, r.iface.Name, orDash(r.iface.Mode), membersText(&r.iface)))
	}
	_ = walk.Clipboard().SetText(b.String())
	walk.MsgBox(p.app, "已复制", "聚合口信息已复制到剪贴板。", walk.MsgBoxIconInformation)
}

// ---------- 页 3: 配置存储网 ----------

func (p *netCfgPages) buildVSPage(nb *walk.TabWidget) (*walk.TabPage, error) {
	page, _ := walk.NewTabPage()
	if err := page.SetLayout(walk.NewVBoxLayout()); err != nil {
		return nil, err
	}
	newPageBar(page, func() { go p.fetchVS() }, &p.vsStat,
		"点击「刷新现网配置」读取各节点存储通信网口配置", p.copyVSState)

	top, bottom := pageBody(page, 120)
	_ = top.SetTitle("当前存储网配置（现网，来自 vs_networksetting_get）")
	p.vsTable, _ = walk.NewTableView(top)
	p.vsModel = &vsModel{}
	p.vsTable.SetModel(p.vsModel)
	addCol(p.vsTable, "节点管理IP", 130)
	addCol(p.vsTable, "hostid", 190)
	addCol(p.vsTable, "存储 IP", 130)
	addCol(p.vsTable, "掩码", 130)
	addCol(p.vsTable, "承载口", 110)
	addCol(p.vsTable, "VLAN", 60)
	addCol(p.vsTable, "类型", 130)
	addCol(p.vsTable, "状态", 70)
	p.vsTable.SetColumnsOrderable(true)
	p.vsTable.SetLastColumnStretched(true)

	_ = bottom.SetTitle("修改存储通信网口（危险写操作）")

	// 自动填充行
	fillRow, _ := mkFormRow(bottom, "起始 IP:", 90)
	p.vsStartIP, _ = walk.NewLineEdit(fillRow)
	setFixedWidth(p.vsStartIP, 160)
	p.vsFillBtn, _ = walk.NewPushButton(fillRow)
	p.vsFillBtn.SetText("按节点顺序自动递增填充")
	setFixedWidth(p.vsFillBtn, 210)
	p.vsFillBtn.Clicked().Attach(p.onVSAutoFill)
	fh, _ := walk.NewLabel(fillRow)
	fh.SetText("（把起始 IP 依次 +1 填给各节点的存储 IP）")
	_, _ = walk.NewHSpacer(fillRow)

	// 每节点一行（节点 / 存储IP / 掩码 / 承载口 / VLAN）
	p.vsScroll, _ = walk.NewScrollView(bottom)
	_ = p.vsScroll.SetLayout(walk.NewVBoxLayout())
	// 最小高度先给一个保守值，实际在 rebuildVSRows 里按节点数重算（且有上限）
	p.vsScroll.SetMinMaxSize(walk.Size{Height: 140}, walk.Size{})
	vsHint, _ := walk.NewLabel(p.vsScroll)
	vsHint.SetText("点击「刷新现网配置」加载各节点存储网配置")

	btnBar, _ := walk.NewComposite(bottom)
	_ = btnBar.SetLayout(walk.NewHBoxLayout())
	p.vsPreview, _ = walk.NewPushButton(btnBar)
	p.vsPreview.SetText("预览变更")
	setFixedWidth(p.vsPreview, 110)
	p.vsPreview.Clicked().Attach(p.onVSPreview)
	p.vsSubmit, _ = walk.NewPushButton(btnBar)
	p.vsSubmit.SetText("校验并提交")
	setFixedWidth(p.vsSubmit, 120)
	p.vsSubmit.Clicked().Attach(p.onVSSubmit)
	_, _ = walk.NewHSpacer(btnBar)
	hint, _ := walk.NewLabel(btnBar)
	hint.SetText("⚠ 存储通信中断会影响虚拟化数据面，请务必确认网段无冲突")

	p.vsDiff = newDiffText(bottom, 60)
	return page, nil
}

// rebuildVSRows 按现网配置 + 节点网口信息重建"每节点一行"的编辑区
func (p *netCfgPages) rebuildVSRows() {
	clearChildren(p.vsScroll)
	p.vsRows = nil

	if len(p.vsSettings) == 0 {
		l, _ := walk.NewLabel(p.vsScroll)
		l.SetText("未获取到存储网配置（设备可能未启用存储网络）")
		return
	}
	byID := groupByHostID(p.vsGroups)

	// 表头
	head, _ := walk.NewComposite(p.vsScroll)
	_ = head.SetLayout(walk.NewHBoxLayout())
	head.SetMinMaxSize(walk.Size{Height: rowHeight}, walk.Size{Height: rowHeight})
	mkHead := func(text string, w int) {
		l, _ := walk.NewLabel(head)
		l.SetText(text)
		if f, err := walk.NewFont("Microsoft YaHei", 9, walk.FontBold); err == nil {
			l.SetFont(f)
		}
		l.SetMinMaxSize(walk.Size{Width: w, Height: 0}, walk.Size{Width: w, Height: 0})
	}
	mkHead("节点", 200)
	mkHead("存储 IP", 140)
	mkHead("掩码", 140)
	mkHead("承载口", 130)
	mkHead("VLAN", 70)

	for _, s := range p.vsSettings {
		row, _ := walk.NewComposite(p.vsScroll)
		_ = row.SetLayout(walk.NewHBoxLayout())
		// 行高固定：否则 ScrollView 的 VBox 会把每行拉高（实测每行被拉到 ~55px，
		// 6 个节点就要滚动才能看全，体验很差）
		row.SetMinMaxSize(walk.Size{Height: rowHeight}, walk.Size{Height: rowHeight})

		name, _ := walk.NewLabel(row)
		name.SetText(p.nodeLabel(s.HostName))
		name.SetMinMaxSize(walk.Size{Width: 200, Height: 0}, walk.Size{Width: 200, Height: 0})

		ipEdit, _ := walk.NewLineEdit(row)
		ipEdit.SetText(s.HostIP)
		setFixedWidth(ipEdit, 140)

		maskEdit, _ := walk.NewLineEdit(row)
		mask := s.Netmask
		if mask == "" {
			mask = "255.255.255.0"
		}
		maskEdit.SetText(mask)
		setFixedWidth(maskEdit, 140)

		// 承载口候选：优先该节点已有聚合口，其次物理口
		var nicVals []string
		if ni, ok := byID[s.HostName]; ok {
			nicVals = bondNamesOf(ni)
			if len(nicVals) == 0 {
				for _, f := range ni.Data {
					if f.Type == "phy-iface" {
						nicVals = append(nicVals, f.Name)
					}
				}
			}
		}
		combo, _ := walk.NewDropDownBox(row)
		combo.SetModel(nicVals)
		setFixedWidth(combo, 140)
		for i, n := range nicVals {
			if contains(s.Nics, n) {
				_ = combo.SetCurrentIndex(i)
				break
			}
		}

		vlanEdit, _ := walk.NewLineEdit(row)
		vlanEdit.SetText(fmt.Sprintf("%d", s.VLANID))
		setFixedWidth(vlanEdit, 80)
		_, _ = walk.NewHSpacer(row)

		p.vsRows = append(p.vsRows, &vsRowCtl{
			hostName: s.HostName,
			hostIP:   s.HostIP,
			ipEdit:   ipEdit,
			maskEdit: maskEdit,
			vlanEdit: vlanEdit,
			nicCombo: combo,
			nicVals:  nicVals,
		})
	}
	// 按 (节点数 + 表头) 行数把滚动区高度调到刚好放得下，避免不必要的滚动条。
	// 但要设上限：节点多时不再把整页"撑高" —— 页面最小高度一旦超过屏幕可用客户区，
	// 窗口最大化后标题栏（最小化/最大化/关闭）会被挤出屏幕（实测 DPI=192 时必现）。
	// 超过上限时交给 ScrollView 自己滚动。
	needH := (len(p.vsRows)+1)*(rowHeight+8) + 4
	if needH < 120 {
		needH = 120
	}
	if needH > 170 {
		needH = 170
	}
	p.vsScroll.SetMinMaxSize(walk.Size{Height: needH}, walk.Size{})
	p.vsScroll.RequestLayout()
}

// onVSAutoFill 按节点顺序，把起始 IP 依次 +1 填入各节点存储 IP
func (p *netCfgPages) onVSAutoFill() {
	start := strings.TrimSpace(p.vsStartIP.Text())
	if !ValidIPv4(start) {
		walk.MsgBox(p.app, "提示", "起始 IP 不合法: "+orDash(start), walk.MsgBoxIconError)
		return
	}
	for i, r := range p.vsRows {
		ip, ok := nextIPv4(start, i)
		if !ok {
			walk.MsgBox(p.app, "提示", "生成的 IP 越界，请换一个起始地址。", walk.MsgBoxIconError)
			return
		}
		r.ipEdit.SetText(ip)
	}
	p.setVSStat(fmt.Sprintf("已按 %d 个节点填充连续存储 IP", len(p.vsRows)))
}

// collectVSSettings 从各节点行收集目标配置，同时生成与现网的 diff
func (p *netCfgPages) collectVSSettings() ([]VSNodeSetting, []cfgDiffRow, error) {
	if len(p.vsRows) == 0 {
		return nil, nil, fmt.Errorf("请先刷新现网配置")
	}
	curByHost := map[string]VSNodeSetting{}
	for _, s := range p.vsSettings {
		curByHost[s.HostName] = s
	}

	var list []VSNodeSetting
	var rows []cfgDiffRow
	seenIP := map[string]string{}
	for _, r := range p.vsRows {
		ip := strings.TrimSpace(r.ipEdit.Text())
		mask := strings.TrimSpace(r.maskEdit.Text())
		vlanStr := strings.TrimSpace(r.vlanEdit.Text())
		cur := curByHost[r.hostName]

		if !ValidIPv4(ip) {
			return nil, nil, fmt.Errorf("%s 的存储 IP 不合法: %s", p.nodeLabel(r.hostName), orDash(ip))
		}
		if !ValidNetmask(mask) {
			return nil, nil, fmt.Errorf("%s 的掩码不合法: %s", p.nodeLabel(r.hostName), orDash(mask))
		}
		if prev, ok := seenIP[ip]; ok {
			return nil, nil, fmt.Errorf("存储 IP 重复: %s（%s 与 %s）", ip, prev, p.nodeLabel(r.hostName))
		}
		seenIP[ip] = p.nodeLabel(r.hostName)
		if vlanStr == "" {
			vlanStr = "0"
		}
		vlan, err := strconv.Atoi(vlanStr)
		if err != nil || vlan < 0 || vlan > 4094 {
			return nil, nil, fmt.Errorf("%s 的 VLAN 不合法: %s（应为 0-4094 的整数）", p.nodeLabel(r.hostName), vlanStr)
		}

		nic := strings.TrimSpace(r.nicCombo.Text())
		if nic == "" {
			return nil, nil, fmt.Errorf("%s 未选择承载口", p.nodeLabel(r.hostName))
		}

		// 严格照抓包复刻的字段组合
		s := VSNodeSetting{
			ServiceIP:  cur.ServiceIP,
			Nics:       []string{nic},
			HostStatus: cur.HostStatus,
			HostAlias:  cur.HostAlias,
			VLANID:     vlan,
			IsNew:      "1",
			HostMask:   cur.HostMask,
			UsedRDMA:   cur.UsedRDMA,
			Hoststatus: cur.Hoststatus,
			HostName:   r.hostName,
			Type:       orDefault(cur.Type, "standard_network"),
			Netmask:    mask,
			HostIP:     ip,
		}
		list = append(list, s)
		rows = append(rows,
			cfgDiffRow{"节点 " + p.nodeLabel(r.hostName), "", ""},
			cfgDiffRow{"  存储 IP", cur.HostIP, ip},
			cfgDiffRow{"  掩码", cur.Netmask, mask},
			cfgDiffRow{"  承载口", strings.Join(cur.Nics, ","), nic},
			cfgDiffRow{"  VLAN", fmt.Sprintf("%d", cur.VLANID), fmt.Sprintf("%d", vlan)},
		)
	}
	return list, rows, nil
}

func (p *netCfgPages) onVSPreview() {
	list, rows, err := p.collectVSSettings()
	if err != nil {
		walk.MsgBox(p.app, "参数有误", err.Error(), walk.MsgBoxIconError)
		return
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("目标存储网配置（%d 个节点）:\n\n", len(list)))
	b.WriteString(formatCfgDiff(rows))
	b.WriteString("\n⚠ 存储通信中断会影响虚拟化数据面，提交前请确认网段与交换机 VLAN 一致！")
	p.vsDiff.SetText(b.String())
	p.setVSStat("已生成预览")
}

// onVSSubmit 第一阶段：本地校验 + 设备侧预校验（不写入）
func (p *netCfgPages) onVSSubmit() {
	a := p.app
	if a.client == nil {
		walk.MsgBox(a, "提示", "请先登录设备。", walk.MsgBoxIconInformation)
		return
	}
	list, rows, err := p.collectVSSettings()
	if err != nil {
		walk.MsgBox(a, "参数有误", err.Error(), walk.MsgBoxIconError)
		return
	}
	p.vsSubmit.SetEnabled(false)
	p.vsSubmit.SetText("校验中...")
	p.setVSStat("正在执行设备侧网段冲突校验...")
	client := a.client
	go func() {
		warnInfo, warnLevel, err := client.CheckArbiterSameNetIP(list)
		a.post("nc_vs_checked", err, vsChecked{list: list, rows: rows, warn: warnInfo, level: warnLevel})
	}()
}

// onVSConfirm 第二阶段（在 UI 线程）：展示 diff + 校验告警，确认后真正下发
func (p *netCfgPages) onVSConfirm(ck vsChecked) {
	a := p.app
	var b strings.Builder
	b.WriteString(fmt.Sprintf("即将写入存储通信网口配置（%d 个节点）:\n\n", len(ck.list)))
	b.WriteString(formatCfgDiff(ck.rows))
	b.WriteString("\n设备侧预校验结果: ")
	if ck.warn != "" {
		b.WriteString(fmt.Sprintf("⚠ level=%d  %s\n", ck.level, ck.warn))
	} else {
		b.WriteString("无告警\n")
	}
	b.WriteString("\n⚠ 此操作非常危险，可能导致存储通信中断、数据面异常！\n")
	b.WriteString("确认执行请点击 [是]，点击 [否] 取消。")
	p.vsDiff.SetText(b.String())

	if ret := walk.MsgBox(a, "危险操作确认", b.String(), walk.MsgBoxYesNo|walk.MsgBoxIconWarning); ret != walk.DlgCmdYes {
		p.vsSubmit.SetEnabled(true)
		p.vsSubmit.SetText("校验并提交")
		p.setVSStat("已取消（未写入）")
		return
	}

	p.vsSubmit.SetText("执行中...")
	p.setVSStat("正在下发存储网配置...")
	client := a.client
	list := ck.list
	go func() {
		upid, err := client.SetVSNetworkSetting(list)
		if err != nil {
			a.post("nc_task_done", err, ncResult{page: "vs"})
			return
		}
		msg, err := client.WaitTask(upid, 5*time.Minute)
		if err != nil {
			a.post("nc_task_done", err, ncResult{page: "vs", msg: msg})
			return
		}
		// 回读：is_net_config 的 type 会由 NONE 变为 standard_network
		note := "任务消息: " + orDash(msg)
		if st, err2 := client.GetNetConfigState(); err2 == nil {
			note += fmt.Sprintf("\n回读 is_net_config: type=%s, is_config=%s",
				orDash(st.Type), orDash(st.IsConfig))
		}
		a.post("nc_task_done", nil, ncResult{page: "vs", msg: "存储网配置任务执行完成", note: note})
	}()
}

func (p *netCfgPages) copyVSState() {
	if len(p.vsSettings) == 0 {
		walk.MsgBox(p.app, "无数据", "当前没有存储网配置数据，请先刷新。", walk.MsgBoxIconInformation)
		return
	}
	var b strings.Builder
	b.WriteString("存储网配置现状:\n")
	for _, s := range p.vsSettings {
		b.WriteString(fmt.Sprintf("%-18s 存储IP %-16s 掩码 %-16s 承载口 %-10s VLAN %d 类型 %s\n",
			s.HostAlias, orDash(s.HostIP), orDash(s.Netmask), strings.Join(s.Nics, ","), s.VLANID, s.Type))
	}
	_ = walk.Clipboard().SetText(b.String())
	walk.MsgBox(p.app, "已复制", "存储网配置已复制到剪贴板。", walk.MsgBoxIconInformation)
}

// ---------- 页 4: 配置业务口 ----------

func (p *netCfgPages) buildBizPage(nb *walk.TabWidget) (*walk.TabPage, error) {
	page, _ := walk.NewTabPage()
	if err := page.SetLayout(walk.NewVBoxLayout()); err != nil {
		return nil, err
	}
	newPageBar(page, func() { go p.fetchBiz() }, &p.bizStat,
		"点击「刷新现网配置」读取当前业务口配置", p.copyBizState)

	top, bottom := pageBody(page, 120)
	_ = top.SetTitle("当前业务口（现网，来自 business-ifaces）")
	p.bizTable, _ = walk.NewTableView(top)
	p.bizModel = &bizModel{}
	p.bizTable.SetModel(p.bizModel)
	addCol(p.bizTable, "节点", 130)
	addCol(p.bizTable, "业务口", 100)
	addCol(p.bizTable, "类型", 90)
	addCol(p.bizTable, "聚合模式", 120)
	addCol(p.bizTable, "成员口", 130)
	addCol(p.bizTable, "状态", 60)
	addCol(p.bizTable, "角色", 110)
	p.bizTable.SetColumnsOrderable(true)
	p.bizTable.SetLastColumnStretched(true)

	_ = bottom.SetTitle("配置业务口（SDN 拓扑「物理出口」节点，危险写操作）")
	p.bizNodes = newCheckGroup(bottom, "目标节点")
	p.bizNodes.onChange = p.refreshBizVLink

	row, _ := mkFormRow(bottom, "承载口:", 90)
	p.bizVLink, _ = walk.NewDropDownBox(row)
	setFixedWidth(p.bizVLink, 150)
	lbUUID, _ := walk.NewLabel(row)
	lbUUID.SetText("  拓扑节点 ID:")
	p.bizUUID, _ = walk.NewLineEdit(row)
	setFixedWidth(p.bizUUID, 330)
	p.bizRegen, _ = walk.NewPushButton(row)
	p.bizRegen.SetText("重新生成")
	setFixedWidth(p.bizRegen, 90)
	_, _ = walk.NewHSpacer(row)
	p.bizRegen.Clicked().Attach(func() { p.bizUUID.SetText(NewUUIDv4()) })

	btnBar, _ := walk.NewComposite(bottom)
	_ = btnBar.SetLayout(walk.NewHBoxLayout())
	p.bizPreview, _ = walk.NewPushButton(btnBar)
	p.bizPreview.SetText("预览变更")
	setFixedWidth(p.bizPreview, 110)
	p.bizPreview.Clicked().Attach(p.onBizPreview)
	p.bizSubmit, _ = walk.NewPushButton(btnBar)
	p.bizSubmit.SetText("校验并提交")
	setFixedWidth(p.bizSubmit, 120)
	p.bizSubmit.Clicked().Attach(p.onBizSubmit)
	_, _ = walk.NewHSpacer(btnBar)
	hint, _ := walk.NewLabel(btnBar)
	hint.SetText("⚠ 业务口用于承载业务流量，配错会影响业务连通")

	p.bizDiff = newDiffText(bottom, 60)
	return page, nil
}

// refreshBizVLink 按勾选节点重建承载口候选（各节点共有的聚合口）
func (p *netCfgPages) refreshBizVLink() {
	ids := p.bizNodes.selected()
	byID := groupByHostID(p.bizGroups)
	var sets [][]string
	for _, id := range ids {
		if ni, ok := byID[id]; ok {
			sets = append(sets, bondNamesOf(ni))
		}
	}
	if len(sets) == 0 {
		p.bizVLink.SetModel(nil)
		return
	}
	common := intersect(sets...)
	_ = p.bizVLink.SetModel(common)
	if len(common) > 0 {
		// 优先选中已被标记为 business 角色的聚合口
		pref := 0
		for i, name := range common {
			if ni, ok := byID[ids[0]]; ok {
				for _, f := range ni.Data {
					if f.Name == name && hasRole(&f, "business") {
						pref = i
					}
				}
			}
		}
		_ = p.bizVLink.SetCurrentIndex(pref)
	}
}

// collectBizInput 收集并校验业务口参数
func (p *netCfgPages) collectBizInput() (nodeIDs []string, vlink, uuid string, err error) {
	nodeIDs = p.bizNodes.selected()
	if len(nodeIDs) == 0 {
		return nil, "", "", fmt.Errorf("请至少勾选一个目标节点")
	}
	// DropDownBox(CBS_DROPDOWNLIST) 的 Text() 即当前选中项
	vlink = strings.TrimSpace(p.bizVLink.Text())
	if vlink == "" {
		return nil, "", "", fmt.Errorf("请选择承载口（聚合口）")
	}
	uuid = strings.TrimSpace(p.bizUUID.Text())
	if uuid == "" {
		return nil, "", "", fmt.Errorf("拓扑节点 ID 为空，请点击「重新生成」")
	}
	return nodeIDs, vlink, uuid, nil
}

// bizPlanText 生成业务口映射方案文本
func (p *netCfgPages) bizPlanText(nodeIDs []string, vlink, uuid string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("拓扑节点 ID: %s\n承载口: %s\n\n将建立以下映射（虚拟交换机 evs → 主机聚合口）:\n", uuid, vlink))
	for _, id := range nodeIDs {
		b.WriteString(fmt.Sprintf("  %-24s → %s\n", p.nodeLabel(id), vlink))
	}
	return b.String()
}

func (p *netCfgPages) onBizPreview() {
	nodeIDs, vlink, uuid, err := p.collectBizInput()
	if err != nil {
		walk.MsgBox(p.app, "参数有误", err.Error(), walk.MsgBoxIconError)
		return
	}
	var b strings.Builder
	b.WriteString("目标业务口配置:\n\n")
	b.WriteString(p.bizPlanText(nodeIDs, vlink, uuid))
	if len(p.bizIfaces) > 0 {
		b.WriteString(fmt.Sprintf("\n设备上已有业务口 %d 个（本操作为新增拓扑节点，不会删除已有配置）。\n", len(p.bizIfaces)))
	} else {
		b.WriteString("\n设备上当前没有任何业务口配置，本次为首次创建。\n")
	}
	b.WriteString("\n⚠ 业务口承载业务流量，配置错误会导致业务不通！")
	p.bizDiff.SetText(b.String())
	p.setBizStat("已生成预览")
}

// onBizSubmit 第一阶段：本地校验 + 设备侧接入检查（不写入）
func (p *netCfgPages) onBizSubmit() {
	a := p.app
	if a.client == nil {
		walk.MsgBox(a, "提示", "请先登录设备。", walk.MsgBoxIconInformation)
		return
	}
	nodeIDs, vlink, uuid, err := p.collectBizInput()
	if err != nil {
		walk.MsgBox(a, "参数有误", err.Error(), walk.MsgBoxIconError)
		return
	}
	p.bizSubmit.SetEnabled(false)
	p.bizSubmit.SetText("校验中...")
	p.setBizStat("正在执行设备侧接入检查...")
	client := a.client
	hostEth := map[string][]string{}
	for _, id := range nodeIDs {
		hostEth[id] = []string{vlink}
	}
	go func() {
		isAccess, err := client.CheckBusinessIface(hostEth, uuid)
		a.post("nc_biz_checked", err, bizChecked{nodeIDs: nodeIDs, vlink: vlink, uuid: uuid, isAccess: isAccess})
	}()
}

// onBizConfirm 第二阶段（在 UI 线程）：展示方案 + 接入检查结果，确认后写入
func (p *netCfgPages) onBizConfirm(ck bizChecked) {
	a := p.app
	var b strings.Builder
	b.WriteString("即将创建业务口（拓扑物理出口）:\n\n")
	b.WriteString(p.bizPlanText(ck.nodeIDs, ck.vlink, ck.uuid))
	b.WriteString("\n设备侧接入检查结果: ")
	if ck.isAccess {
		b.WriteString("⚠ is_access_iface = true（该口可能是接入口，请确认不会抢占现有用途）\n")
	} else {
		b.WriteString("is_access_iface = false（正常）\n")
	}
	b.WriteString("\n⚠ 此操作非常危险，可能导致业务网络中断！\n")
	b.WriteString("确认执行请点击 [是]，点击 [否] 取消。")
	p.bizDiff.SetText(b.String())

	if ret := walk.MsgBox(a, "危险操作确认", b.String(), walk.MsgBoxYesNo|walk.MsgBoxIconWarning); ret != walk.DlgCmdYes {
		p.bizSubmit.SetEnabled(true)
		p.bizSubmit.SetText("校验并提交")
		p.setBizStat("已取消（未写入）")
		return
	}

	p.bizSubmit.SetText("执行中...")
	p.setBizStat("正在创建业务口...")
	client := a.client
	bridges := make([]NetPortalBridge, 0, len(ck.nodeIDs))
	for _, id := range ck.nodeIDs {
		bridges = append(bridges, NewNetPortalBridge(id, ck.vlink))
	}
	uuid := ck.uuid
	go func() {
		taskID, err := client.AddNetworkPortalNodes(uuid, bridges)
		if err != nil {
			a.post("nc_task_done", err, ncResult{page: "biz"})
			return
		}
		msg, err := client.WaitTask(taskID, 3*time.Minute)
		if err != nil {
			a.post("nc_task_done", err, ncResult{page: "biz", msg: msg})
			return
		}
		a.post("nc_task_done", nil, ncResult{page: "biz",
			msg: "业务口创建任务执行完成", note: fmt.Sprintf("拓扑节点 ID: %s\n任务消息: %s", uuid, orDash(msg))})
	}()
}

func (p *netCfgPages) copyBizState() {
	if len(p.bizIfaces) == 0 {
		walk.MsgBox(p.app, "无数据", "当前没有业务口配置（或尚未刷新）。", walk.MsgBoxIconInformation)
		return
	}
	var b strings.Builder
	b.WriteString("业务口现状:\n")
	for _, f := range p.bizIfaces {
		b.WriteString(fmt.Sprintf("%-18s %-10s %-14s 成员 %s\n",
			ifaceNodeText(f), f.Name, orDash(f.Mode), membersText(&f)))
	}
	_ = walk.Clipboard().SetText(b.String())
	walk.MsgBox(p.app, "已复制", "业务口信息已复制到剪贴板。", walk.MsgBoxIconInformation)
}

// ---------- 后台拉取 ----------

func (p *netCfgPages) fetchPools() {
	c := p.app.client
	if c == nil {
		return
	}
	pools, err := c.GetVXLANIPPools()
	if err != nil {
		p.app.post("nc_pool_done", err, nil)
		return
	}
	p.app.post("nc_pool_done", nil, poolLoad{pools: pools})
}

func (p *netCfgPages) fetchBonds() {
	c := p.app.client
	if c == nil {
		return
	}
	groups, err := c.GetAllIfaces()
	if err != nil {
		p.app.post("nc_bond_done", err, nil)
		return
	}
	p.app.post("nc_bond_done", nil, bondLoad{groups: groups})
}

func (p *netCfgPages) fetchVS() {
	c := p.app.client
	if c == nil {
		return
	}
	var d vsLoad
	if s, err := c.GetVSNetworkSetting(); err != nil {
		d.errs = append(d.errs, "存储网配置: "+shortErr(err))
	} else {
		d.settings = s
	}
	if g, err := c.GetAllIfaces(); err != nil {
		d.errs = append(d.errs, "网口信息: "+shortErr(err))
	} else {
		d.groups = g
	}
	p.app.post("nc_vs_done", nil, d)
}

func (p *netCfgPages) fetchBiz() {
	c := p.app.client
	if c == nil {
		return
	}
	var d bizLoad
	if f, err := c.GetBusinessIfaces(true); err != nil {
		d.errs = append(d.errs, "业务口: "+shortErr(err))
	} else {
		d.ifaces = f
	}
	if g, err := c.GetAllIfaces(); err != nil {
		d.errs = append(d.errs, "网口信息: "+shortErr(err))
	} else {
		d.groups = g
	}
	p.app.post("nc_biz_done", nil, d)
}

// refreshAll 4 个页面一起刷新（登录后与"刷新全部"时调用）
func (p *netCfgPages) refreshAll() {
	go p.fetchPools()
	go p.fetchBonds()
	go p.fetchVS()
	go p.fetchBiz()
}

// ---------- 状态与标签 ----------

func (p *netCfgPages) setPoolStat(s string) {
	if p.poolStat != nil {
		p.poolStat.SetText(s)
	}
}

func (p *netCfgPages) setBondStat(s string) {
	if p.bondStat != nil {
		p.bondStat.SetText(s)
	}
}

func (p *netCfgPages) setVSStat(s string) {
	if p.vsStat != nil {
		p.vsStat.SetText(s)
	}
}

func (p *netCfgPages) setBizStat(s string) {
	if p.bizStat != nil {
		p.bizStat.SetText(s)
	}
}

// nodeLabel 返回 "管理IP (hostid)" 形式，取不到时退回 hostid
func (p *netCfgPages) nodeLabel(hostID string) string {
	for _, n := range p.app.nodes {
		if n.Hostid == hostID {
			if n.IP != "" {
				return fmt.Sprintf("%s (%s)", n.IP, hostID)
			}
			if n.Node != "" {
				return fmt.Sprintf("%s (%s)", n.Node, hostID)
			}
		}
	}
	return hostID
}

// rebuildNodePickers 节点列表就绪后重建 4 个页面的节点勾选框
func (p *netCfgPages) rebuildNodePickers() {
	var ids, labels []string
	for _, n := range p.app.nodes {
		if !strings.HasPrefix(n.Hostid, "host-") {
			continue
		}
		ids = append(ids, n.Hostid)
		labels = append(labels, fmt.Sprintf("%s (%s)", orDash(n.IP), n.Hostid))
	}
	if p.poolNodes != nil {
		p.poolNodes.rebuild(ids, labels, true)
	}
	if p.bondNodes != nil {
		p.bondNodes.rebuild(ids, labels, true)
		p.refreshBondMembers()
	}
	if p.bizNodes != nil {
		p.bizNodes.rebuild(ids, labels, true)
		p.refreshBizVLink()
	}
	// 端口聚合页的模式候选：抓包实测值优先，再并入设备现网用到的模式
	modes := append([]string{}, BondModeCandidates...)
	seen := map[string]bool{}
	for _, m := range modes {
		seen[m] = true
	}
	for _, g := range p.bondGroups {
		for _, f := range g.Data {
			if f.Type == "bond" && f.Mode != "" && !seen[f.Mode] {
				seen[f.Mode] = true
				modes = append(modes, f.Mode)
			}
		}
	}
	if p.bondMode != nil {
		cur := p.bondMode.Text()
		_ = p.bondMode.SetModel(modes)
		if cur != "" {
			p.bondMode.SetText(cur)
		} else if len(modes) > 0 {
			p.bondMode.SetText(modes[0])
		}
	}
}

// ---------- 事件处理（由 main.go 的 handleEvent 兜底调用） ----------

// vsChecked / bizChecked 预校验结果（回到 UI 线程后再弹确认框）
type vsChecked struct {
	list  []VSNodeSetting
	rows  []cfgDiffRow
	warn  string
	level int
}

type bizChecked struct {
	nodeIDs  []string
	vlink    string
	uuid     string
	isAccess bool
}

// handleNetCfgEvent 处理 4 个配置页的事件；未识别返回 false 交回主流程
func (a *App) handleNetCfgEvent(ev uiEvent) bool {
	p := a.nc
	if p == nil {
		return false
	}
	switch ev.kind {
	case "nc_pool_done":
		if ev.err != nil {
			p.setPoolStat("读取失败: " + shortErr(ev.err))
			p.poolDiff.SetText("读取 VXLAN IP 池失败:\n" + ev.err.Error())
			return true
		}
		d := ev.data.(poolLoad)
		p.poolCur = d.pools
		p.poolModel.items = d.pools
		p.poolModel.PublishRowsReset()
		if len(d.pools) == 0 {
			p.setPoolStat("设备上当前没有任何 VXLAN IP 池")
		} else {
			p.setPoolStat(fmt.Sprintf("现网共 %d 个 VXLAN IP 池", len(d.pools)))
		}
		return true

	case "nc_bond_done":
		if ev.err != nil {
			p.setBondStat("读取失败: " + shortErr(ev.err))
			p.bondDiff.SetText("读取网口信息失败:\n" + ev.err.Error())
			return true
		}
		d := ev.data.(bondLoad)
		p.bondGroups = d.groups
		rows := bondsOf(d.groups)
		p.bondModel.items = rows
		p.bondModel.PublishRowsReset()
		p.setBondStat(fmt.Sprintf("现网共 %d 个聚合口（已排除被占用的物理口）", len(rows)))
		p.rebuildNodePickers()
		return true

	case "nc_vs_done":
		d := ev.data.(vsLoad)
		p.vsSettings = d.settings
		p.vsGroups = d.groups
		p.vsModel.items = d.settings
		p.vsModel.PublishRowsReset()
		p.rebuildVSRows()
		if len(d.errs) > 0 {
			p.setVSStat("部分读取失败: " + strings.Join(d.errs, "; "))
		} else {
			p.setVSStat(fmt.Sprintf("现网共 %d 个节点的存储网配置", len(d.settings)))
		}
		return true

	case "nc_biz_done":
		d := ev.data.(bizLoad)
		p.bizIfaces = d.ifaces
		p.bizGroups = d.groups
		p.bizModel.items = d.ifaces
		p.bizModel.PublishRowsReset()
		if len(d.errs) > 0 {
			p.setBizStat("部分读取失败: " + strings.Join(d.errs, "; "))
		} else if len(d.ifaces) == 0 {
			p.setBizStat("设备上当前未配置业务口")
		} else {
			p.setBizStat(fmt.Sprintf("现网共 %d 个业务口", len(d.ifaces)))
		}
		p.refreshBizVLink()
		return true

	case "nc_vs_checked":
		p.vsSubmit.SetEnabled(true)
		p.vsSubmit.SetText("校验并提交")
		if ev.err != nil {
			p.setVSStat("预校验失败: " + shortErr(ev.err))
			walk.MsgBox(a, "预校验失败", "设备侧校验未通过，已中止提交：\n\n"+ev.err.Error(), walk.MsgBoxIconError)
			return true
		}
		p.setVSStat("预校验通过，等待确认")
		p.onVSConfirm(ev.data.(vsChecked))
		return true

	case "nc_biz_checked":
		p.bizSubmit.SetEnabled(true)
		p.bizSubmit.SetText("校验并提交")
		if ev.err != nil {
			p.setBizStat("接入检查失败: " + shortErr(ev.err))
			walk.MsgBox(a, "接入检查失败", "设备侧检查未通过，已中止提交：\n\n"+ev.err.Error(), walk.MsgBoxIconError)
			return true
		}
		p.setBizStat("接入检查完成，等待确认")
		p.onBizConfirm(ev.data.(bizChecked))
		return true

	case "nc_task_done":
		res, _ := ev.data.(ncResult)
		// 恢复按钮
		switch res.page {
		case "pool":
			p.poolSubmit.SetEnabled(true)
			p.poolPreview.SetEnabled(true)
			p.poolSubmit.SetText("提交下发")
		case "bond":
			p.bondSubmit.SetEnabled(true)
			p.bondPreview.SetEnabled(true)
			p.bondSubmit.SetText("提交创建")
		case "vs":
			p.vsSubmit.SetEnabled(true)
			p.vsSubmit.SetText("校验并提交")
		case "biz":
			p.bizSubmit.SetEnabled(true)
			p.bizSubmit.SetText("校验并提交")
		}
		if ev.err != nil {
			p.appendResult(res, "执行失败: "+ev.err.Error(), true)
			walk.MsgBox(a, "任务失败", ev.err.Error(), walk.MsgBoxIconError)
			return true
		}
		p.appendResult(res, res.msg, false)
		walk.MsgBox(a, "执行完成", res.msg+"\n\n"+res.note, walk.MsgBoxIconInformation)
		p.reloadAfterSubmit(res.page)
		return true
	}
	return false
}

// appendResult 把结果追加到对应页面的 diff 文本框
func (p *netCfgPages) appendResult(res ncResult, msg string, isErr bool) {
	prefix := "\n[执行结果] "
	if isErr {
		prefix = "\n[执行失败] "
	}
	text := prefix + msg + "\n"
	if res.note != "" {
		text += res.note + "\n"
	}
	appendTo := func(te *walk.TextEdit) {
		if te != nil {
			te.AppendText(text)
		}
	}
	switch res.page {
	case "pool":
		appendTo(p.poolDiff)
		p.setPoolStat(msg)
	case "bond":
		appendTo(p.bondDiff)
		p.setBondStat(msg)
	case "vs":
		appendTo(p.vsDiff)
		p.setVSStat(msg)
	case "biz":
		appendTo(p.bizDiff)
		p.setBizStat(msg)
	}
}

// reloadAfterSubmit 写操作成功后回读现网，让"现网"表格反映最新状态
func (p *netCfgPages) reloadAfterSubmit(page string) {
	switch page {
	case "pool":
		go p.fetchPools()
	case "bond":
		go p.fetchBonds()
		p.app.refreshIfaces()
		go p.app.fetchVXLAN()
	case "vs":
		go p.fetchVS()
		p.app.refreshIfaces()
	case "biz":
		go p.fetchBiz()
		p.app.refreshIfaces()
	}
}

// ---------- 小工具 ----------

// contains 判断字符串切片是否含某项
func contains(list []string, s string) bool {
	for _, it := range list {
		if it == s {
			return true
		}
	}
	return false
}

// orDefault 为空时返回默认值
func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
