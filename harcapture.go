package main

// harcapture.go —— 可配置的调试抓包（把每一次 HTTP 请求/响应写成标准 HAR 1.2 文件）
//
// 开关项：配置文件 <可执行文件同目录>/.sangfor-config.json 里的
//
//	debug.capture_har   （bool，默认 false = 关闭）
//
// 存放路径：debug.har_dir 指定；留空则用 <可执行文件同目录>/har/<yyyy-MM-dd>/
// 文件命名：sangfor-<设备地址>-<yyyyMMdd-HHmmss>-p<pid>.har
//
//	单文件条目数超过 debug.har_max_entries_per_file 时自动滚动：
//	sangfor-<设备地址>-<yyyyMMdd-HHmmss>-p<pid>-2.har、-3.har …
//
// 其它选项：
//
//	debug.har_max_entries_per_file  单文件最多记录多少条请求（默认 500，超出后滚动新文件）
//	debug.har_max_body_kb           单条请求/响应体最多保留多少 KB（默认 2048，超出截断并标记）
//	debug.har_mask_secrets          是否对 Cookie/CSRF/密码等敏感值脱敏（默认 true，强烈建议保持）
//
// 设计要点：
//   - 抓包挂钩在 HTTP 的唯一出口（Client.doBody）上，所以"任何涉及网络的操作"都会被记录；
//   - 每条记录后立即落盘（临时文件 + rename 原子替换），程序被强杀也不会丢已抓到的报文；
//   - HAR 里默认把会话凭据脱敏，但文件本身仍属敏感数据，不要外发、不要提交仓库。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// appVersion 程序版本（写进 HAR 的 creator 字段）
const appVersion = "1.0.0"

// ---------- 配置文件 ----------

// appConfigName 配置文件文件名（与可执行文件同目录）
const appConfigName = ".sangfor-config.json"

// appConfig 程序运行配置（当前只有调试抓包相关项，后续可扩展）
type appConfig struct {
	Comment string      `json:"_说明,omitempty"`
	Debug   debugConfig `json:"debug"`
}

// debugConfig 调试相关配置
type debugConfig struct {
	// CaptureHAR 抓包总开关：true = 对所有网络请求抓包并写入 HAR 文件；默认 false（关闭）
	CaptureHAR bool `json:"capture_har"`
	// HARDir HAR 存放目录；留空表示默认 <可执行文件同目录>/har
	HARDir string `json:"har_dir"`
	// HARMaxEntries 单个 HAR 文件最多记录多少条请求；超出后在同目录滚动出下一个分片文件
	HARMaxEntries int `json:"har_max_entries_per_file"`
	// HARMaxBodyKB 单条请求体/响应体最多保留多少 KB（超出截断并在 HAR 里标记）
	HARMaxBodyKB int `json:"har_max_body_kb"`
	// HARMaskSecrets 是否对 Cookie / CSRF 令牌 / 密码等敏感值脱敏（默认 true）
	HARMaskSecrets bool `json:"har_mask_secrets"`
}

// defaultAppConfig 默认配置：抓包**关闭**
func defaultAppConfig() appConfig {
	return appConfig{
		Comment: "本文件是 sangfor-ifaces 的运行配置。debug.capture_har=true 时会对所有网络请求抓包，" +
			"并按 HAR 1.2 写入 <可执行文件同目录>/har/<日期>/ 下（文件名 sangfor-<设备地址>-<时间>-p<pid>.har）。" +
			"抓包文件含会话凭据（默认已脱敏），请勿外发或提交到代码仓库。修改后需重启程序生效。",
		Debug: debugConfig{
			CaptureHAR:     false,
			HARDir:         "",
			HARMaxEntries:  500,
			HARMaxBodyKB:   2048,
			HARMaskSecrets: true,
		},
	}
}

// exeDir 可执行文件所在目录（取不到时用当前目录）
func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		if wd, werr := os.Getwd(); werr == nil {
			return wd
		}
		return "."
	}
	return filepath.Dir(exe)
}

// exeDirHook 取"程序所在目录"的函数；单独抽出来便于测试替换
var exeDirHook = exeDir

// appConfigFile 配置文件全路径
func appConfigFile() string { return filepath.Join(exeDirHook(), appConfigName) }

// loadAppConfig 读取配置文件；文件不存在时**生成一份默认配置（抓包关闭）**并返回默认值。
// 文件存在但解析失败时保留原文件内容不动（只提示），返回默认值，避免误覆盖用户配置。
func loadAppConfig() (appConfig, error) {
	def := defaultAppConfig()
	data, err := os.ReadFile(appConfigFile())
	if err != nil {
		if os.IsNotExist(err) {
			if werr := writeDefaultAppConfig(); werr != nil {
				return def, fmt.Errorf("配置文件不存在且写入默认配置失败: %w", werr)
			}
			return def, nil
		}
		return def, err
	}
	var cfg appConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return def, fmt.Errorf("配置文件解析失败（已按默认值运行，抓包关闭）: %w", err)
	}
	// 缺省值兜底（用户可能只写了 capture_har）
	if cfg.Debug.HARMaxEntries <= 0 {
		cfg.Debug.HARMaxEntries = def.Debug.HARMaxEntries
	}
	if cfg.Debug.HARMaxBodyKB <= 0 {
		cfg.Debug.HARMaxBodyKB = def.Debug.HARMaxBodyKB
	}
	return cfg, nil
}

// writeDefaultAppConfig 写一份带说明的默认配置（抓包关闭）
func writeDefaultAppConfig() error {
	def := defaultAppConfig()
	data, err := json.MarshalIndent(def, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(appConfigFile(), append(data, '\n'), 0600)
}

// harRootDir HAR 根目录：配置指定优先，否则 <可执行文件同目录>/har
func (c appConfig) harRootDir() string {
	if dir := strings.TrimSpace(c.Debug.HARDir); dir != "" {
		return dir
	}
	return filepath.Join(exeDirHook(), "har")
}

// ---------- HAR 数据结构（HAR 1.2） ----------

type harFile struct {
	Log harLog `json:"log"`
}

type harLog struct {
	Version string     `json:"version"`
	Creator harCreator `json:"creator"`
	Comment string     `json:"comment,omitempty"`
	Pages   []harPage  `json:"pages"`
	Entries []harEntry `json:"entries"`
}

type harCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type harPage struct {
	StartedDateTime string         `json:"startedDateTime"`
	ID              string         `json:"id"`
	Title           string         `json:"title"`
	PageTimings     harPageTimings `json:"pageTimings"`
}

type harPageTimings struct {
	OnContentLoad float64 `json:"onContentLoad"`
	OnLoad        float64 `json:"onLoad"`
}

type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
	Cache           struct{}    `json:"cache"`
	Timings         harTimings  `json:"timings"`
	ServerIPAddress string      `json:"serverIPAddress,omitempty"`
	PageRef         string      `json:"pageref,omitempty"`
	Comment         string      `json:"comment,omitempty"`
}

type harRequest struct {
	Method      string   `json:"method"`
	URL         string   `json:"url"`
	HTTPVersion string   `json:"httpVersion"`
	Cookies     []harNVP `json:"cookies"`
	Headers     []harNVP `json:"headers"`
	QueryString []harNVP `json:"queryString"`
	HeadersSize int      `json:"headersSize"`
	BodySize    int      `json:"bodySize"`
	PostData    *harPost `json:"postData,omitempty"`
}

type harPost struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type harResponse struct {
	Status      int        `json:"status"`
	StatusText  string     `json:"statusText"`
	HTTPVersion string     `json:"httpVersion"`
	Cookies     []harNVP   `json:"cookies"`
	Headers     []harNVP   `json:"headers"`
	Content     harContent `json:"content"`
	RedirectURL string     `json:"redirectURL"`
	HeadersSize int        `json:"headersSize"`
	BodySize    int        `json:"bodySize"`
}

type harContent struct {
	Size      int    `json:"size"`
	MimeType  string `json:"mimeType"`
	Text      string `json:"text"`
	Truncated bool   `json:"_truncated,omitempty"`
}

type harTimings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

type harNVP struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ---------- 敏感信息脱敏 ----------

const harMasked = "<已脱敏>"

var harSensitiveHeader = map[string]bool{
	"cookie":                true,
	"set-cookie":            true,
	"csrfpreventiontoken":   true,
	"x-csrfpreventiontoken": true,
	"authorization":         true,
}

// harSensitiveFormRe 表单/查询串里的敏感字段（password=xxx&csrf_token=xxx）
// 字段名里**含** password / pwd / secret / ticket / token / cookie 的都算敏感（如 csrf_token、login_cookie）
var harSensitiveFormRe = regexp.MustCompile(`(?i)(^|[&?])([A-Za-z0-9_]*(?:password|passwd|pwd|secret|ticket|token|cookie)[A-Za-z0-9_]*)=([^&]*)`)

// harSensitiveJSONRe JSON body 里的敏感字段（"password": "xxx"）
var harSensitiveJSONRe = regexp.MustCompile(`(?i)"([A-Za-z0-9_]*(?:password|passwd|pwd|secret|ticket|token|cookie)[A-Za-z0-9_]*)"(\s*:\s*)"[^"]*"`)

func harMaskText(s string) string {
	if s == "" {
		return s
	}
	out := harSensitiveFormRe.ReplaceAllString(s, "${1}${2}="+harMasked)
	out = harSensitiveJSONRe.ReplaceAllString(out, `"${1}"${2}"`+harMasked+`"`)
	return out
}

// ---------- 记录器 ----------

type harRecorder struct {
	mu         sync.Mutex
	rootDir    string // HAR 根目录
	hostTag    string // 设备地址标签（用于文件名）
	sessTime   time.Time
	part       int
	maxEntries int
	maxBody    int
	mask       bool

	pageID    string
	startedAt time.Time
	entries   []harEntry
	path      string // 当前正在写的文件全路径
}

// har 全局记录器；nil 表示抓包关闭
var har *harRecorder

// harInit 按配置初始化抓包（关闭时把记录器置 nil）
func harInit(cfg appConfig) {
	if !cfg.Debug.CaptureHAR {
		har = nil
		return
	}
	har = &harRecorder{
		rootDir:    cfg.harRootDir(),
		sessTime:   time.Now(),
		part:       1, // 1 = 首个文件（无 -N 后缀），滚动后 2、3…
		maxEntries: cfg.Debug.HARMaxEntries,
		maxBody:    cfg.Debug.HARMaxBodyKB * 1024,
		mask:       cfg.Debug.HARMaskSecrets,
	}
}

// harEnabled 抓包是否开启
func harEnabled() bool { return har != nil }

// harDirForToday 今天这批抓包的目录（<根目录>/<yyyy-MM-dd>）
func (h *harRecorder) dirForToday() string {
	return filepath.Join(h.rootDir, h.sessTime.Format("2006-01-02"))
}

// fileFor 当前分片的文件名
func (h *harRecorder) fileFor() string {
	name := fmt.Sprintf("sangfor-%s-%s-p%d", h.hostTag, h.sessTime.Format("20060102-150405"), os.Getpid())
	if h.part > 1 {
		name = fmt.Sprintf("%s-%d", name, h.part)
	}
	return filepath.Join(h.dirForToday(), name+".har")
}

// record 记一条请求/响应（reqErr 非空表示请求本身失败，此时没有响应）
func (h *harRecorder) record(req *http.Request, reqBody []byte, status int, respHeader http.Header,
	respBody []byte, took time.Duration, reqErr error) {

	h.mu.Lock()
	defer h.mu.Unlock()

	// 单文件条目达到上限 → 滚动到下一个分片（注意：路径也要清空，否则新分片会写回旧文件）
	if len(h.entries) >= h.maxEntries {
		h.part++
		h.entries = nil
		h.path = ""
	}
	if h.hostTag == "" {
		h.hostTag = hostTagOf(req.URL)
	}
	if h.path == "" {
		h.startedAt = time.Now()
		h.pageID = "sangfor-session"
	}

	entry := harEntry{
		StartedDateTime: time.Now().Add(-took).Format(time.RFC3339Nano),
		PageRef:         h.pageID,
		Time:            float64(took.Microseconds()) / 1000.0,
		Request:         h.buildRequest(req, reqBody),
		Response:        h.buildResponse(status, respHeader, respBody, reqErr),
		Timings:         harTimings{Wait: float64(took.Microseconds()) / 1000.0},
	}
	if reqErr != nil {
		entry.Comment = "请求失败：" + reqErr.Error()
	}
	h.entries = append(h.entries, entry)
	h.flushLocked()
}

func (h *harRecorder) buildRequest(req *http.Request, body []byte) harRequest {
	headers := make([]harNVP, 0, len(req.Header))
	names := make([]string, 0, len(req.Header))
	for k := range req.Header {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		v := strings.Join(req.Header.Values(k), ", ")
		if h.mask && harSensitiveHeader[strings.ToLower(k)] {
			v = harMasked
		}
		headers = append(headers, harNVP{Name: k, Value: v})
	}
	// Cookie：按 HAR 规范放进 cookies 数组（值脱敏），不额外伪造 Cookie 头
	cookies := make([]harNVP, 0)
	for _, c := range req.Cookies() {
		v := c.Value
		if h.mask {
			v = harMasked
		}
		cookies = append(cookies, harNVP{Name: c.Name, Value: v})
	}

	q := make([]harNVP, 0)
	for k, vs := range req.URL.Query() {
		for _, v := range vs {
			if h.mask {
				v = harMaskText(v)
			}
			q = append(q, harNVP{Name: k, Value: v})
		}
	}

	r := harRequest{
		Method:      req.Method,
		URL:         req.URL.String(),
		HTTPVersion: "HTTP/1.1",
		Cookies:     cookies,
		Headers:     headers,
		QueryString: q,
		HeadersSize: -1,
		BodySize:    len(body),
	}
	if len(body) > 0 {
		text, truncated := h.bodyText(body)
		r.PostData = &harPost{
			MimeType: req.Header.Get("Content-Type"),
			Text:     maskBody(h.mask, text) + truncNote(truncated),
		}
	}
	return r
}

func (h *harRecorder) buildResponse(status int, hdr http.Header, body []byte, reqErr error) harResponse {
	if reqErr != nil {
		return harResponse{
			Status: 0, StatusText: "(无响应)", HTTPVersion: "HTTP/1.1",
			Cookies: []harNVP{}, Headers: []harNVP{},
			Content:     harContent{Size: 0, MimeType: "", Text: ""},
			HeadersSize: -1, BodySize: -1,
		}
	}
	headers := make([]harNVP, 0, len(hdr))
	names := make([]string, 0, len(hdr))
	for k := range hdr {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		v := strings.Join(hdr.Values(k), ", ")
		if h.mask && harSensitiveHeader[strings.ToLower(k)] {
			v = harMasked
		}
		headers = append(headers, harNVP{Name: k, Value: v})
	}
	text, truncated := h.bodyText(body)
	return harResponse{
		Status:      status,
		StatusText:  http.StatusText(status),
		HTTPVersion: "HTTP/1.1",
		Cookies:     []harNVP{},
		Headers:     headers,
		Content: harContent{
			Size:      len(body),
			MimeType:  hdr.Get("Content-Type"),
			Text:      maskBody(h.mask, text),
			Truncated: truncated,
		},
		HeadersSize: -1,
		BodySize:    len(body),
	}
}

// bodyText 截断超长 body（超过 maxBody 时保留前 maxBody 字节）
func (h *harRecorder) bodyText(body []byte) (string, bool) {
	if h.maxBody > 0 && len(body) > h.maxBody {
		return string(body[:h.maxBody]), true
	}
	return string(body), false
}

func maskBody(mask bool, s string) string {
	if !mask {
		return s
	}
	return harMaskText(s)
}

func truncNote(truncated bool) string {
	if truncated {
		return "\n…（已按 har_max_body_kb 截断）"
	}
	return ""
}

// flushLocked 原子落盘（先写临时文件再 rename，避免半截文件）
func (h *harRecorder) flushLocked() {
	if h.path == "" {
		h.path = h.fileFor()
	}
	if err := os.MkdirAll(filepath.Dir(h.path), 0700); err != nil {
		return
	}
	f := harFile{Log: harLog{
		Version: "1.2",
		Creator: harCreator{Name: "sangfor-ifaces-gui", Version: appVersion},
		Comment: "由本工具内置调试抓包生成；敏感值默认已脱敏（debug.har_mask_secrets）。" +
			"设备地址：" + h.hostTag,
		Pages: []harPage{{
			StartedDateTime: h.startedAt.Format(time.RFC3339Nano),
			ID:              h.pageID,
			Title:           "sangfor-ifaces 会话",
			PageTimings:     harPageTimings{OnContentLoad: -1, OnLoad: -1},
		}},
		Entries: h.entries,
	}}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return
	}
	tmp := h.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0600); err != nil {
		return
	}
	_ = os.Rename(tmp, h.path)
}

// hostTagOf 从请求 URL 生成"设备地址"标签（用于文件名，去掉协议与斜杠，端口用下划线）
func hostTagOf(u *url.URL) string {
	host := u.Host
	if host == "" {
		return "unknown"
	}
	host = strings.TrimPrefix(host, "//")
	r := strings.NewReplacer(":", "_", "/", "_", "\\", "_", " ", "")
	return r.Replace(host)
}

// harRecord 抓包入口（未开启时直接返回）
func harRecord(req *http.Request, reqBody []byte, status int, respHeader http.Header,
	respBody []byte, took time.Duration, reqErr error) {
	if har == nil || req == nil {
		return
	}
	har.record(req, reqBody, status, respHeader, respBody, took, reqErr)
}

// harStatusText 给界面/日志用的开关状态描述
func harStatusText(cfg appConfig) string {
	if !cfg.Debug.CaptureHAR {
		return "抓包：关闭（配置文件 debug.capture_har=false）"
	}
	dir := cfg.harRootDir()
	if !filepath.IsAbs(dir) {
		if abs, err := filepath.Abs(dir); err == nil {
			dir = abs
		}
	}
	return "抓包：已开启 → " + dir
}
