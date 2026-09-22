package main

// harcapture_test.go —— 调试抓包（HAR）单元测试
// 覆盖：默认关闭 / 配置读写 / 脱敏 / 文件命名与分片 / HAR 结构可被标准解析 / 关闭时不写文件

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withTempExeDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := exeDirHook
	exeDirHook = func() string { return dir }
	t.Cleanup(func() { exeDirHook = old })
	return dir
}

// 默认配置必须是"抓包关闭"
func TestDefaultAppConfigCaptureOff(t *testing.T) {
	cfg := defaultAppConfig()
	if cfg.Debug.CaptureHAR {
		t.Fatalf("默认配置应当是抓包关闭，实际 capture_har=%v", cfg.Debug.CaptureHAR)
	}
	if !cfg.Debug.HARMaskSecrets {
		t.Fatal("默认应当对敏感值脱敏")
	}
	if cfg.Debug.HARMaxEntries <= 0 || cfg.Debug.HARMaxBodyKB <= 0 {
		t.Fatal("默认上限应当为正数")
	}
}

// 配置文件不存在 → 自动生成一份（开关为关闭）并返回默认值
func TestLoadAppConfigCreatesDefaultFile(t *testing.T) {
	dir := withTempExeDir(t)
	cfg, err := loadAppConfig()
	if err != nil {
		t.Fatalf("loadAppConfig: %v", err)
	}
	if cfg.Debug.CaptureHAR {
		t.Fatal("新生成的配置应当是关闭状态")
	}
	raw, err := os.ReadFile(filepath.Join(dir, appConfigName))
	if err != nil {
		t.Fatalf("应当生成默认配置文件: %v", err)
	}
	var got appConfig
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("生成的配置文件不是合法 JSON: %v", err)
	}
	if got.Debug.CaptureHAR {
		t.Fatal("生成文件里的 capture_har 必须是 false")
	}
	// 文件里应写明开关名与路径说明（方便用户找到）
	if !strings.Contains(string(raw), "capture_har") || !strings.Contains(string(raw), "_说明") {
		t.Fatal("生成的配置应含 capture_har 与 _说明")
	}
}

// 改开关 → 读得到；缺省项自动补默认值
func TestLoadAppConfigReadsSwitch(t *testing.T) {
	dir := withTempExeDir(t)
	body := `{"debug":{"capture_har":true}}`
	if err := os.WriteFile(filepath.Join(dir, appConfigName), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadAppConfig()
	if err != nil {
		t.Fatalf("loadAppConfig: %v", err)
	}
	if !cfg.Debug.CaptureHAR {
		t.Fatal("capture_har=true 应当读到 true")
	}
	if cfg.Debug.HARMaxEntries != defaultAppConfig().Debug.HARMaxEntries {
		t.Fatal("未写的上限项应当回落到默认值")
	}
	// 未开启时不应创建记录器
	harInit(cfg)
	if !harEnabled() {
		t.Fatal("开启后 harEnabled 应为 true")
	}
	harInit(defaultAppConfig())
	if harEnabled() {
		t.Fatal("关闭后 harEnabled 应为 false")
	}
}

// 敏感值脱敏
func TestHarMaskText(t *testing.T) {
	cases := []string{
		"username=admin&password=U2FsdGVkX1+abc==",
		`{"password":"secret123","user":"admin"}`,
		`{"csrf_token":"deadbeef"}`,
	}
	for _, c := range cases {
		got := harMaskText(c)
		if strings.Contains(got, "U2FsdGVkX1") || strings.Contains(got, "secret123") || strings.Contains(got, "deadbeef") {
			t.Fatalf("未脱敏: %s -> %s", c, got)
		}
		if !strings.Contains(got, harMasked) {
			t.Fatalf("应当出现脱敏标记: %s -> %s", c, got)
		}
	}
	// 非敏感内容不受影响
	if got := harMaskText("username=admin&role=mgmt"); got != "username=admin&role=mgmt" {
		t.Fatalf("普通内容不该被改动: %s", got)
	}
	if !strings.Contains(harMaskText("csrf_token=x"), harMasked) {
		t.Fatal("_token 这类下划线字段也要脱敏")
	}
}

// 文件名标签
func TestHostTagOf(t *testing.T) {
	mk := func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return hostTagOf(u)
	}
	if got := mk("https://192.168.131.179/vapi/json/x"); got != "192.168.131.179" {
		t.Fatalf("got %q", got)
	}
	if got := mk("https://127.0.0.1:8443/vapi/json/x"); got != "127.0.0.1_8443" {
		t.Fatalf("带端口应替换冒号, got %q", got)
	}
}

// 文件命名规则 + 分片
func TestHarFileNamingAndRotation(t *testing.T) {
	dir := withTempExeDir(t)
	cfg := defaultAppConfig()
	cfg.Debug.CaptureHAR = true
	cfg.Debug.HARMaxEntries = 2 // 便于验证分片
	harInit(cfg)
	defer harInit(defaultAppConfig())

	h := har
	h.hostTag = "192.168.131.179"
	h.sessTime = time.Date(2026, 9, 21, 22, 30, 5, 0, time.Local)

	p1 := h.fileFor()
	wantDir := filepath.Join(dir, "har", "2026-09-21")
	if filepath.Dir(p1) != wantDir {
		t.Fatalf("目录应为 <exe目录>/har/<yyyy-MM-dd>，实际 %s", filepath.Dir(p1))
	}
	wantName := "sangfor-192.168.131.179-20260921-223005-p" + itoa(os.Getpid()) + ".har"
	if filepath.Base(p1) != wantName {
		t.Fatalf("文件名规则不符：\n got %s\nwant %s", filepath.Base(p1), wantName)
	}
	h.part = 2
	if filepath.Base(h.fileFor()) != strings.TrimSuffix(wantName, ".har")+"-2.har" {
		t.Fatalf("分片名应为 ...-2.har，实际 %s", filepath.Base(h.fileFor()))
	}
	h.part = 1
}

// 抓一条 → 生成合法 HAR，字段与脱敏都正确
func TestHarRecordWritesValidHAR(t *testing.T) {
	dir := withTempExeDir(t)
	cfg := defaultAppConfig()
	cfg.Debug.CaptureHAR = true
	harInit(cfg)
	defer harInit(defaultAppConfig())

	form := url.Values{}
	form.Set("username", "admin")
	form.Set("password", "U2FsdGVkX1+PLAIN")
	reqBody := []byte(form.Encode())

	req, err := http.NewRequest(http.MethodPost, "https://192.168.131.179/vapi/extjs/access/ticket", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Cookie", "LoginAuthCookie=SECRET-COOKIE")
	req.Header.Set("CSRFPreventionToken", "SECRET-TOKEN")
	req.Header.Set("Referer", "https://192.168.131.179/login")

	respHdr := http.Header{}
	respHdr.Set("Content-Type", "application/json; charset=UTF-8")
	respHdr.Add("Set-Cookie", "LoginAuthCookie=SECRET-COOKIE")
	respBody := []byte(`{"success":1,"data":{"CSRFPreventionToken":"SECRET-TOKEN"}}`)

	harRecord(req, reqBody, 200, respHdr, respBody, 37*time.Millisecond, nil)

	files, err := filepath.Glob(filepath.Join(dir, "har", "*", "*.har"))
	if err != nil || len(files) != 1 {
		t.Fatalf("应当生成 1 个 HAR 文件，实际 %v (err=%v)", files, err)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "SECRET-COOKIE") || strings.Contains(string(raw), "SECRET-TOKEN") ||
		strings.Contains(string(raw), "U2FsdGVkX1+PLAIN") {
		t.Fatal("HAR 里不应出现明文凭据/口令")
	}

	var f harFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("HAR 不是合法 JSON: %v", err)
	}
	if f.Log.Version != "1.2" || len(f.Log.Entries) != 1 {
		t.Fatalf("HAR 结构不对: version=%s entries=%d", f.Log.Version, len(f.Log.Entries))
	}
	e := f.Log.Entries[0]
	if e.Request.Method != "POST" || !strings.Contains(e.Request.URL, "/vapi/extjs/access/ticket") {
		t.Fatalf("request 记录不对: %+v", e.Request)
	}
	if e.Response.Status != 200 || !strings.Contains(e.Response.Content.Text, `"success":1`) {
		t.Fatalf("response 记录不对: %+v", e.Response)
	}
	if e.Request.PostData == nil || !strings.Contains(e.Request.PostData.Text, "username=admin") {
		t.Fatalf("请求体应当保留非敏感字段: %+v", e.Request.PostData)
	}
	if e.Time <= 0 {
		t.Fatal("time 应当大于 0")
	}
	// Cookie 头必须脱敏
	var cookieMasked bool
	for _, h := range e.Request.Headers {
		if strings.EqualFold(h.Name, "Cookie") {
			cookieMasked = h.Value == harMasked
		}
	}
	if !cookieMasked {
		t.Fatal("Cookie 头应当被脱敏")
	}
	// 临时文件不应残留
	if _, err := os.Stat(files[0] + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("不应残留 .tmp 文件")
	}
}

// 关闭时不产生任何文件（默认行为）
func TestHarDisabledWritesNothing(t *testing.T) {
	dir := withTempExeDir(t)
	harInit(defaultAppConfig())
	if harEnabled() {
		t.Fatal("默认应当关闭")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://192.168.131.179/vapi/json/cluster/nodelist", nil)
	harRecord(req, nil, 200, http.Header{}, []byte(`{"success":1}`), time.Millisecond, nil)
	if _, err := os.Stat(filepath.Join(dir, "har")); !os.IsNotExist(err) {
		t.Fatal("关闭时不应创建 har 目录/文件")
	}
}

// 分片：超过 har_max_entries_per_file 后滚动到下一个文件
func TestHarRotatesWhenEntriesExceedLimit(t *testing.T) {
	dir := withTempExeDir(t)
	cfg := defaultAppConfig()
	cfg.Debug.CaptureHAR = true
	cfg.Debug.HARMaxEntries = 2
	harInit(cfg)
	defer harInit(defaultAppConfig())

	req, _ := http.NewRequest(http.MethodGet, "https://192.168.131.179/vapi/json/cluster/nodelist", nil)
	for i := 0; i < 5; i++ {
		harRecord(req, nil, 200, http.Header{}, []byte(`{"success":1}`), time.Millisecond, nil)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "har", "*", "*.har"))
	if len(files) != 3 {
		t.Fatalf("5 条记录 / 每个文件 2 条 → 应滚动出 3 个文件，实际 %d: %v", len(files), files)
	}
	// 分片文件名带 -2 / -3
	var has2, has3 bool
	for _, f := range files {
		b := filepath.Base(f)
		has2 = has2 || strings.Contains(b, "-2.har")
		has3 = has3 || strings.Contains(b, "-3.har")
	}
	if !has2 || !has3 {
		t.Fatalf("分片名应含 -2/-3: %v", files)
	}
}

// 请求失败也要留痕（status=0 + comment）
func TestHarRecordsFailedRequest(t *testing.T) {
	dir := withTempExeDir(t)
	cfg := defaultAppConfig()
	cfg.Debug.CaptureHAR = true
	harInit(cfg)
	defer harInit(defaultAppConfig())

	req, _ := http.NewRequest(http.MethodGet, "https://192.168.131.179/vapi/json/x", nil)
	harRecord(req, nil, 0, nil, nil, time.Second, errString("dial tcp: connect timeout"))

	files, _ := filepath.Glob(filepath.Join(dir, "har", "*", "*.har"))
	if len(files) != 1 {
		t.Fatalf("失败请求也应记录，实际文件数 %d", len(files))
	}
	raw, _ := os.ReadFile(files[0])
	if !strings.Contains(string(raw), "connect timeout") {
		t.Fatal("HAR 中应能看到失败原因")
	}
}

// ---------- 小工具 ----------

type errString string

func (e errString) Error() string { return string(e) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}
