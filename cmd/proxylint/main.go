package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-telegram/bot"
)

type ProxyKind string

const (
	KindVLESS   ProxyKind = "vless"
	KindVMess   ProxyKind = "vmess"
	KindTrojan  ProxyKind = "trojan"
	KindSS      ProxyKind = "ss"
	KindSocks5  ProxyKind = "socks5"
	KindHTTP    ProxyKind = "http"
	KindTGSOCKS ProxyKind = "telegram-socks"
	KindTGMT    ProxyKind = "telegram-mtproto"
)

type Proxy struct {
	Raw      string
	Kind     ProxyKind
	Name     string
	Host     string
	Port     int
	UUID     string
	Password string
	Method   string
	Network  string
	TLS      bool
	SNI      string
	Path     string
	HostHdr  string
	Remark   string
	Secret   string
	Security string
}

type CheckResult struct {
	Raw       string        `json:"raw"`
	Kind      string        `json:"kind"`
	Connected bool          `json:"connected"`
	Latency   time.Duration `json:"latency"`
	Core      string        `json:"core"`
	Error     string        `json:"error,omitempty"`
}

type CoreMode string

const (
	CoreAny     CoreMode = "any"
	CoreXray    CoreMode = "xray"
	CoreSingBox CoreMode = "sing-box"
	CoreBoth    CoreMode = "both"
)

type Options struct {
	SingleProxy string
	InputFile   string
	OutputFile  string
	FailedFile  string
	JSONFile    string
	Timeout     time.Duration
	Retries     int
	RetryDelay  time.Duration
	Concurrency int
	ProbeURL    string
	CoreMode    CoreMode
	XrayBin    string
	SingBoxBin string
}

func main() {
	if len(os.Args) < 2 || os.Args[1] != "check" {
		fmt.Println("Usage: proxylint check [flags]")
		os.Exit(2)
	}

	fs := flag.NewFlagSet("check", flag.ExitOnError)
	var opt Options
	fs.StringVar(&opt.SingleProxy, "proxy", "", "single proxy URI to check")
	fs.StringVar(&opt.InputFile, "in", "", "input file with proxies, one per line")
	fs.StringVar(&opt.OutputFile, "out", "valid.txt", "output file for valid proxies")
	fs.StringVar(&opt.FailedFile, "failed", "", "optional output file for failed proxies")
	fs.StringVar(&opt.JSONFile, "json", "", "optional JSON report output file")
	fs.DurationVar(&opt.Timeout, "timeout", 8*time.Second, "per-check timeout")
	fs.IntVar(&opt.Retries, "retries", 1, "retry count per core")
	fs.DurationVar(&opt.RetryDelay, "retry-delay", 300*time.Millisecond, "delay between retries")
	fs.IntVar(&opt.Concurrency, "concurrency", 30, "number of concurrent checks")
	fs.StringVar(&opt.ProbeURL, "probe-url", "https://www.google.com/generate_204", "probe URL")
	coreMode := fs.String("core", "any", "core mode: any|xray|sing-box|both")
	fs.StringVar(&opt.XrayBin, "xray-bin", "xray", "xray binary path")
	fs.StringVar(&opt.SingBoxBin, "singbox-bin", "sing-box", "sing-box binary path")

	_ = fs.Parse(os.Args[2:])
	opt.CoreMode = CoreMode(strings.ToLower(strings.TrimSpace(*coreMode)))

	if opt.SingleProxy == "" && opt.InputFile == "" {
		fmt.Fprintln(os.Stderr, "need one of --proxy or --in")
		os.Exit(2)
	}
	if opt.Concurrency < 1 {
		opt.Concurrency = 1
	}
	if opt.Retries < 0 {
		opt.Retries = 0
	}
	if !isValidCoreMode(opt.CoreMode) {
		fmt.Fprintln(os.Stderr, "invalid --core, expected any|xray|sing-box|both")
		os.Exit(2)
	}
	if _, err := url.ParseRequestURI(opt.ProbeURL); err != nil {
		fmt.Fprintf(os.Stderr, "invalid --probe-url: %v\n", err)
		os.Exit(2)
	}

	raws, err := loadInputs(opt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load input: %v\n", err)
		os.Exit(2)
	}
	if len(raws) == 0 {
		fmt.Fprintln(os.Stderr, "no proxies found")
		os.Exit(2)
	}

	proxies := make([]Proxy, 0, len(raws))
	parseFails := 0
	for _, raw := range raws {
		p, err := parseProxy(raw)
		if err != nil {
			fmt.Printf("FAIL parse %q: %v\n", raw, err)
			parseFails++
			continue
		}
		proxies = append(proxies, p)
	}

	results := runChecks(proxies, opt)
	writeOutputs(results, opt)

	passed := 0
	for _, r := range results {
		if r.Connected {
			passed++
		}
		status := "FAIL"
		if r.Connected {
			status = "OK"
		}
		if r.Error != "" {
			fmt.Printf("%s [%s] %s (%s) err=%s\n", status, r.Core, r.Kind, r.Raw, r.Error)
		} else {
			fmt.Printf("%s [%s] %s (%s) latency=%s\n", status, r.Core, r.Kind, r.Raw, r.Latency)
		}
	}

	fmt.Printf("done: total=%d parsed=%d parse_fail=%d passed=%d failed=%d\n", len(raws), len(proxies), parseFails, passed, len(results)-passed)
	if parseFails > 0 || passed != len(results) {
		os.Exit(1)
	}
}

func isValidCoreMode(m CoreMode) bool {
	switch m {
	case CoreAny, CoreXray, CoreSingBox, CoreBoth:
		return true
	default:
		return false
	}
}

func loadInputs(opt Options) ([]string, error) {
	items := make([]string, 0)
	if strings.TrimSpace(opt.SingleProxy) != "" {
		items = append(items, strings.TrimSpace(opt.SingleProxy))
	}
	if strings.TrimSpace(opt.InputFile) == "" {
		return uniq(items), nil
	}
	b, err := os.ReadFile(opt.InputFile)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	for _, ln := range lines {
		v := strings.TrimSpace(ln)
		if v == "" || strings.HasPrefix(v, "#") {
			continue
		}
		items = append(items, v)
	}
	return uniq(items), nil
}

func uniq(in []string) []string {
	m := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := m[v]; ok {
			continue
		}
		m[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func parseProxy(raw string) (Proxy, error) {
	if strings.HasPrefix(raw, "mtproto://") {
		return parseMTProtoURI(raw)
	}
	if strings.HasPrefix(raw, "https://t.me/proxy?") || strings.HasPrefix(raw, "tg://proxy?") {
		return parseTelegram(raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Proxy{}, err
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "vless":
		return parseVLESS(raw, u)
	case "trojan":
		return parseTrojan(raw, u)
	case "vmess":
		return parseVMess(raw, u)
	case "ss":
		return parseSS(raw, u)
	case "socks", "socks5":
		return parseSocks(raw, u, KindSocks5)
	case "http", "https":
		return parseSocks(raw, u, KindHTTP)
	default:
		return Proxy{}, fmt.Errorf("unsupported scheme: %s", scheme)
	}
}

func parseMTProtoURI(raw string) (Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Proxy{}, err
	}
	h, p, err := net.SplitHostPort(u.Host)
	if err != nil {
		return Proxy{}, err
	}
	pi, _ := strconv.Atoi(p)
	q := u.Query()
	secret := q.Get("secret")
	if secret == "" {
		secret = strings.TrimPrefix(u.Opaque, "//")
	}
	if secret == "" {
		secret = strings.TrimPrefix(u.Fragment, "#")
	}
	if secret == "" {
		return Proxy{}, errors.New("mtproto secret is required")
	}
	return Proxy{Raw: raw, Kind: KindTGMT, Host: h, Port: pi, Secret: secret}, nil
}

func parseTelegram(raw string) (Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Proxy{}, err
	}
	q := u.Query()
	if server := q.Get("server"); server != "" {
		port, _ := strconv.Atoi(q.Get("port"))
		if q.Get("secret") != "" {
			return Proxy{Raw: raw, Kind: KindTGMT, Host: server, Port: port, Secret: q.Get("secret")}, nil
		}
		if q.Get("user") != "" || q.Get("username") != "" {
			user := q.Get("user")
			if user == "" {
				user = q.Get("username")
			}
			pass := q.Get("pass")
			if pass == "" {
				pass = q.Get("password")
			}
			return Proxy{Raw: raw, Kind: KindTGSOCKS, Host: server, Port: port, UUID: user, Password: pass}, nil
		}
	}
	return Proxy{}, errors.New("invalid telegram proxy format")
}

func parseVLESS(raw string, u *url.URL) (Proxy, error) {
	h, p, err := net.SplitHostPort(u.Host)
	if err != nil {
		return Proxy{}, err
	}
	pi, _ := strconv.Atoi(p)
	q := u.Query()
	remark, _ := url.QueryUnescape(strings.TrimPrefix(u.Fragment, "#"))
	return Proxy{
		Raw:      raw,
		Kind:     KindVLESS,
		Host:     h,
		Port:     pi,
		UUID:     u.User.Username(),
		TLS:      q.Get("security") == "tls" || q.Get("security") == "reality",
		SNI:      q.Get("sni"),
		Network:  defaultStr(q.Get("type"), "tcp"),
		Path:     q.Get("path"),
		HostHdr:  q.Get("host"),
		Remark:   remark,
		Security: q.Get("security"),
	}, nil
}

func parseTrojan(raw string, u *url.URL) (Proxy, error) {
	h, p, err := net.SplitHostPort(u.Host)
	if err != nil {
		return Proxy{}, err
	}
	pi, _ := strconv.Atoi(p)
	q := u.Query()
	return Proxy{
		Raw:      raw,
		Kind:     KindTrojan,
		Host:     h,
		Port:     pi,
		Password: u.User.Username(),
		TLS:      true,
		SNI:      q.Get("sni"),
		Network:  defaultStr(q.Get("type"), "tcp"),
		Path:     q.Get("path"),
		HostHdr:  q.Get("host"),
	}, nil
}

func parseVMess(raw string, u *url.URL) (Proxy, error) {
	enc := strings.TrimPrefix(raw, "vmess://")
	b, err := base64.RawStdEncoding.DecodeString(enc)
	if err != nil {
		b, err = base64.StdEncoding.DecodeString(enc)
		if err != nil {
			return Proxy{}, fmt.Errorf("invalid vmess payload")
		}
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return Proxy{}, err
	}
	pi, _ := strconv.Atoi(m["port"])
	if pi == 0 {
		pi, _ = strconv.Atoi(m["addport"])
	}
	return Proxy{
		Raw:      raw,
		Kind:     KindVMess,
		Host:     m["add"],
		Port:     pi,
		UUID:     m["id"],
		TLS:      m["tls"] == "tls",
		SNI:      m["sni"],
		Network:  defaultStr(m["net"], "tcp"),
		Path:     m["path"],
		HostHdr:  m["host"],
		Security: m["security"],
	}, nil
}

func parseSS(raw string, u *url.URL) (Proxy, error) {
	content := strings.TrimPrefix(raw, "ss://")
	part := content
	if at := strings.LastIndex(content, "@"); at == -1 {
		decoded, err := base64DecodeLenient(content)
		if err != nil {
			return Proxy{}, err
		}
		part = decoded
	}

	var userinfo, hostport string
	if i := strings.LastIndex(part, "@"); i >= 0 {
		userinfo = part[:i]
		hostport = part[i+1:]
	} else {
		return Proxy{}, errors.New("invalid ss format")
	}

	if strings.Contains(hostport, "#") {
		hostport = strings.SplitN(hostport, "#", 2)[0]
	}
	if strings.Contains(hostport, "?") {
		hostport = strings.SplitN(hostport, "?", 2)[0]
	}
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return Proxy{}, err
	}
	pi, _ := strconv.Atoi(p)
	if strings.Contains(userinfo, ":") {
		sp := strings.SplitN(userinfo, ":", 2)
		return Proxy{Raw: raw, Kind: KindSS, Host: h, Port: pi, Method: sp[0], Password: sp[1]}, nil
	}
	decoded, err := base64DecodeLenient(userinfo)
	if err != nil {
		return Proxy{}, err
	}
	sp := strings.SplitN(decoded, ":", 2)
	if len(sp) != 2 {
		return Proxy{}, errors.New("invalid ss userinfo")
	}
	return Proxy{Raw: raw, Kind: KindSS, Host: h, Port: pi, Method: sp[0], Password: sp[1]}, nil
}

func parseSocks(raw string, u *url.URL, kind ProxyKind) (Proxy, error) {
	h, p, err := net.SplitHostPort(u.Host)
	if err != nil {
		return Proxy{}, err
	}
	pi, _ := strconv.Atoi(p)
	pass, _ := u.User.Password()
	return Proxy{Raw: raw, Kind: kind, Host: h, Port: pi, UUID: u.User.Username(), Password: pass}, nil
}

func base64DecodeLenient(in string) (string, error) {
	in = strings.TrimSpace(in)
	in = strings.TrimSuffix(in, "/")
	b, err := base64.RawURLEncoding.DecodeString(in)
	if err == nil {
		return string(b), nil
	}
	b, err = base64.URLEncoding.DecodeString(in)
	if err == nil {
		return string(b), nil
	}
	b, err = base64.RawStdEncoding.DecodeString(in)
	if err == nil {
		return string(b), nil
	}
	b, err = base64.StdEncoding.DecodeString(in)
	if err == nil {
		return string(b), nil
	}
	return "", err
}

func defaultStr(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}

func runChecks(proxies []Proxy, opt Options) []CheckResult {
	jobs := make(chan Proxy)
	results := make(chan CheckResult, len(proxies))

	var wg sync.WaitGroup
	workers := opt.Concurrency
	if workers > len(proxies) {
		workers = len(proxies)
	}
	if workers < 1 {
		workers = 1
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				results <- checkProxy(p, opt)
			}
		}()
	}

	for _, p := range proxies {
		jobs <- p
	}
	close(jobs)

	wg.Wait()
	close(results)

	out := make([]CheckResult, 0, len(proxies))
	for r := range results {
		out = append(out, r)
	}
	return out
}

func checkProxy(p Proxy, opt Options) CheckResult {
	if isTelegramKind(p.Kind) {
		return checkTelegramProxy(p, opt)
	}

	cores := selectedCores(opt.CoreMode)
	bestFail := CheckResult{Raw: p.Raw, Kind: string(p.Kind), Connected: false, Core: strings.Join(cores, ",")}
	allOK := true

	for _, core := range cores {
		res := tryCoreWithRetry(p, core, opt)
		if res.Connected {
			if opt.CoreMode != CoreBoth {
				return res
			}
			continue
		}
		allOK = false
		bestFail = res
		if opt.CoreMode == CoreAny {
			continue
		}
		if opt.CoreMode == CoreXray || opt.CoreMode == CoreSingBox {
			return res
		}
	}

	if opt.CoreMode == CoreBoth {
		if allOK {
			return CheckResult{Raw: p.Raw, Kind: string(p.Kind), Connected: true, Core: "both"}
		}
		return bestFail
	}

	return bestFail
}

func isTelegramKind(k ProxyKind) bool {
	return k == KindTGSOCKS || k == KindTGMT
}

func checkTelegramProxy(p Proxy, opt Options) CheckResult {
	var last CheckResult
	for i := 0; i <= opt.Retries; i++ {
		res := runSingleTelegramCheck(p, opt)
		if res.Connected {
			return res
		}
		last = res
		if i < opt.Retries {
			time.Sleep(opt.RetryDelay)
		}
	}
	return last
}

func runSingleTelegramCheck(p Proxy, opt Options) CheckResult {
	ctx, cancel := context.WithTimeout(context.Background(), opt.Timeout)
	defer cancel()

	switch p.Kind {
	case KindTGSOCKS:
		return doTGSocksCheck(ctx, p, opt)
	case KindTGMT:
		return doTGMtprotoCheck(ctx, p, opt)
	default:
		return CheckResult{Raw: p.Raw, Kind: string(p.Kind), Core: "telegram", Error: "unsupported telegram kind"}
	}
}

func doTGSocksCheck(ctx context.Context, p Proxy, opt Options) CheckResult {
	res := CheckResult{Raw: p.Raw, Kind: string(p.Kind), Core: "telegram"}

	proxyURL := &url.URL{
		Scheme: "socks5",
		Host:   net.JoinHostPort(p.Host, strconv.Itoa(p.Port)),
	}
	if p.UUID != "" {
		proxyURL.User = url.UserPassword(p.UUID, p.Password)
	}

	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	client := &http.Client{Timeout: opt.Timeout, Transport: transport}

	b, err := bot.New("0", bot.WithHTTPClient(opt.Timeout, client))
	if err != nil {
		res.Error = err.Error()
		return res
	}

	start := time.Now()
	_, err = b.GetMe(ctx)
	res.Latency = time.Since(start)

	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) {
			res.Error = trimErr(err.Error())
			return res
		}
		res.Connected = true
		return res
	}
	res.Connected = true
	return res
}

func doTGMtprotoCheck(ctx context.Context, p Proxy, opt Options) CheckResult {
	res := CheckResult{Raw: p.Raw, Kind: string(p.Kind), Core: "telegram"}
	addr := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))

	dialer := net.Dialer{Timeout: opt.Timeout}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer conn.Close()

	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)

	buf := make([]byte, 64)
	if _, err := rand.Read(buf); err != nil {
		res.Error = err.Error()
		return res
	}
	buf[0] = 0xee

	if _, err := conn.Write(buf); err != nil {
		res.Latency = time.Since(start)
		res.Error = err.Error()
		return res
	}

	resp := make([]byte, 1)
	_, err = conn.Read(resp)
	res.Latency = time.Since(start)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Connected = true
	return res
}

func selectedCores(mode CoreMode) []string {
	switch mode {
	case CoreXray:
		return []string{"xray"}
	case CoreSingBox:
		return []string{"sing-box"}
	case CoreBoth:
		return []string{"xray", "sing-box"}
	default:
		return []string{"xray", "sing-box"}
	}
}

func tryCoreWithRetry(p Proxy, core string, opt Options) CheckResult {
	var last CheckResult
	for i := 0; i <= opt.Retries; i++ {
		res := runSingleCoreCheck(p, core, opt)
		if res.Connected {
			return res
		}
		last = res
		if i < opt.Retries {
			time.Sleep(opt.RetryDelay)
		}
	}
	return last
}

func runSingleCoreCheck(p Proxy, core string, opt Options) CheckResult {
	res := CheckResult{Raw: p.Raw, Kind: string(p.Kind), Core: core}
	localPort, err := freePort()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	var cfg []byte
	if core == "xray" {
		cfg, err = buildXrayConfig(p, localPort)
	} else {
		cfg, err = buildSingBoxConfig(p, localPort)
	}
	if err != nil {
		res.Error = err.Error()
		return res
	}

	tmp, err := os.MkdirTemp("", "proxylint-*")
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer os.RemoveAll(tmp)

	cfgPath := filepath.Join(tmp, "config.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		res.Error = err.Error()
		return res
	}

	ctx, cancel := context.WithTimeout(context.Background(), opt.Timeout)
	defer cancel()

	var cmd *exec.Cmd
	if core == "xray" {
		cmd = exec.CommandContext(ctx, opt.XrayBin, "run", "-c", cfgPath)
	} else {
		cmd = exec.CommandContext(ctx, opt.SingBoxBin, "run", "-c", cfgPath)
	}
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		res.Error = err.Error()
		return res
	}

	errBuf := &strings.Builder{}
	go io.Copy(io.Discard, stdout)
	go io.Copy(errBuf, stderr)

	time.Sleep(650 * time.Millisecond)
	start := time.Now()
	err = probeThroughLocal(localPort, opt.ProbeURL, opt.Timeout)
	res.Latency = time.Since(start)

	_ = cmd.Process.Kill()
	_ = cmd.Wait()

	if err != nil {
		msg := err.Error()
		if errBuf.Len() > 0 {
			msg = strings.TrimSpace(errBuf.String())
		}
		res.Error = trimErr(msg)
		return res
	}
	res.Connected = true
	return res
}

func trimErr(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 250 {
		return v[:250]
	}
	return v
}

func probeThroughLocal(port int, target string, timeout time.Duration) error {
	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	t := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	client := &http.Client{Timeout: timeout, Transport: t}
	req, _ := http.NewRequest(http.MethodGet, target, nil)
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		return fmt.Errorf("http status %d", res.StatusCode)
	}
	return nil
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func buildXrayConfig(p Proxy, localPort int) ([]byte, error) {
	outbound, err := xrayOutboundFor(p)
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"tag":      "socks-in",
			"listen":   "127.0.0.1",
			"port":     localPort,
			"protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": true},
		}},
		"outbounds": []any{outbound, map[string]any{"protocol": "direct", "tag": "direct"}},
		"routing":   map[string]any{"rules": []any{map[string]any{"type": "field", "inboundTag": []string{"socks-in"}, "outboundTag": "proxy"}}},
	}
	return json.Marshal(cfg)
}

func xrayOutboundFor(p Proxy) (map[string]any, error) {
	switch p.Kind {
	case KindVLESS:
		stream := map[string]any{"network": p.Network}
		if p.TLS {
			stream["security"] = "tls"
			tlsCfg := map[string]any{}
			if p.SNI != "" {
				tlsCfg["serverName"] = p.SNI
			}
			stream["tlsSettings"] = tlsCfg
		}
		if p.Network == "ws" {
			stream["wsSettings"] = map[string]any{"path": defaultStr(p.Path, "/"), "headers": map[string]any{"Host": p.HostHdr}}
		}
		return map[string]any{
			"tag":            "proxy",
			"protocol":       "vless",
			"settings":       map[string]any{"vnext": []any{map[string]any{"address": p.Host, "port": p.Port, "users": []any{map[string]any{"id": p.UUID, "encryption": "none"}}}}, "decryption": "none"},
			"streamSettings": stream,
		}, nil
	case KindTrojan:
		stream := map[string]any{"network": p.Network, "security": "tls", "tlsSettings": map[string]any{"serverName": p.SNI}}
		if p.Network == "ws" {
			stream["wsSettings"] = map[string]any{"path": defaultStr(p.Path, "/"), "headers": map[string]any{"Host": p.HostHdr}}
		}
		return map[string]any{
			"tag":            "proxy",
			"protocol":       "trojan",
			"settings":       map[string]any{"servers": []any{map[string]any{"address": p.Host, "port": p.Port, "password": p.Password}}},
			"streamSettings": stream,
		}, nil
	case KindVMess:
		stream := map[string]any{"network": p.Network}
		if p.TLS {
			stream["security"] = "tls"
			if p.SNI != "" {
				stream["tlsSettings"] = map[string]any{"serverName": p.SNI}
			}
		}
		if p.Network == "ws" {
			stream["wsSettings"] = map[string]any{"path": defaultStr(p.Path, "/"), "headers": map[string]any{"Host": p.HostHdr}}
		}
		return map[string]any{
			"tag":            "proxy",
			"protocol":       "vmess",
			"settings":       map[string]any{"vnext": []any{map[string]any{"address": p.Host, "port": p.Port, "users": []any{map[string]any{"id": p.UUID, "security": defaultStr(p.Security, "auto")}}}}},
			"streamSettings": stream,
		}, nil
	case KindSS:
		return map[string]any{"tag": "proxy", "protocol": "shadowsocks", "settings": map[string]any{"servers": []any{map[string]any{"address": p.Host, "port": p.Port, "method": p.Method, "password": p.Password}}}}, nil
	case KindSocks5, KindTGSOCKS:
		server := map[string]any{"address": p.Host, "port": p.Port}
		if p.UUID != "" {
			server["users"] = []any{map[string]any{"user": p.UUID, "pass": p.Password}}
		}
		return map[string]any{"tag": "proxy", "protocol": "socks", "settings": map[string]any{"servers": []any{server}}}, nil
	case KindHTTP:
		server := map[string]any{"address": p.Host, "port": p.Port}
		if p.UUID != "" {
			server["users"] = []any{map[string]any{"user": p.UUID, "pass": p.Password}}
		}
		return map[string]any{"tag": "proxy", "protocol": "http", "settings": map[string]any{"servers": []any{server}}}, nil
	case KindTGMT:
		return map[string]any{"tag": "proxy", "protocol": "mtproto", "settings": map[string]any{"servers": []any{map[string]any{"address": p.Host, "port": p.Port, "users": []any{map[string]any{"secret": p.Secret}}}}}}, nil
	default:
		return nil, fmt.Errorf("unsupported proxy type for xray: %s", p.Kind)
	}
}

func buildSingBoxConfig(p Proxy, localPort int) ([]byte, error) {
	outbound, err := singboxOutboundFor(p)
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{
			"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": localPort,
		}},
		"outbounds": []any{outbound, map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"rules": []any{map[string]any{"inbound": []string{"socks-in"}, "outbound": "proxy"}}},
	}
	return json.Marshal(cfg)
}

func singboxOutboundFor(p Proxy) (map[string]any, error) {
	switch p.Kind {
	case KindVLESS:
		o := map[string]any{"type": "vless", "tag": "proxy", "server": p.Host, "server_port": p.Port, "uuid": p.UUID, "tls": map[string]any{"enabled": p.TLS}}
		if p.SNI != "" {
			o["tls"].(map[string]any)["server_name"] = p.SNI
		}
		if p.Network == "ws" {
			o["transport"] = map[string]any{"type": "ws", "path": defaultStr(p.Path, "/"), "headers": map[string]any{"Host": p.HostHdr}}
		}
		return o, nil
	case KindTrojan:
		o := map[string]any{"type": "trojan", "tag": "proxy", "server": p.Host, "server_port": p.Port, "password": p.Password, "tls": map[string]any{"enabled": true}}
		if p.SNI != "" {
			o["tls"].(map[string]any)["server_name"] = p.SNI
		}
		if p.Network == "ws" {
			o["transport"] = map[string]any{"type": "ws", "path": defaultStr(p.Path, "/"), "headers": map[string]any{"Host": p.HostHdr}}
		}
		return o, nil
	case KindVMess:
		o := map[string]any{"type": "vmess", "tag": "proxy", "server": p.Host, "server_port": p.Port, "uuid": p.UUID, "security": defaultStr(p.Security, "auto"), "tls": map[string]any{"enabled": p.TLS}}
		if p.SNI != "" {
			o["tls"].(map[string]any)["server_name"] = p.SNI
		}
		if p.Network == "ws" {
			o["transport"] = map[string]any{"type": "ws", "path": defaultStr(p.Path, "/"), "headers": map[string]any{"Host": p.HostHdr}}
		}
		return o, nil
	case KindSS:
		return map[string]any{"type": "shadowsocks", "tag": "proxy", "server": p.Host, "server_port": p.Port, "method": p.Method, "password": p.Password}, nil
	case KindSocks5, KindTGSOCKS:
		o := map[string]any{"type": "socks", "tag": "proxy", "server": p.Host, "server_port": p.Port}
		if p.UUID != "" {
			o["username"] = p.UUID
			o["password"] = p.Password
		}
		return o, nil
	case KindHTTP:
		o := map[string]any{"type": "http", "tag": "proxy", "server": p.Host, "server_port": p.Port}
		if p.UUID != "" {
			o["username"] = p.UUID
			o["password"] = p.Password
		}
		return o, nil
	case KindTGMT:
		return map[string]any{"type": "direct", "tag": "proxy"}, errors.New("sing-box does not support mtproto outbound")
	default:
		return nil, fmt.Errorf("unsupported proxy type for sing-box: %s", p.Kind)
	}
}

func writeOutputs(results []CheckResult, opt Options) {
	validSet := map[string]struct{}{}
	failedSet := map[string]struct{}{}
	valid := make([]string, 0)
	failed := make([]string, 0)
	for _, r := range results {
		if r.Connected {
			if _, ok := validSet[r.Raw]; !ok {
				validSet[r.Raw] = struct{}{}
				valid = append(valid, r.Raw)
			}
			delete(failedSet, r.Raw)
		} else {
			if _, ok := validSet[r.Raw]; !ok {
				if _, seen := failedSet[r.Raw]; !seen {
					failedSet[r.Raw] = struct{}{}
					failed = append(failed, r.Raw)
				}
			}
		}
	}

	if len(valid) > 0 {
		for i := 0; i < len(failed); i++ {
			if _, ok := validSet[failed[i]]; ok {
				failed = append(failed[:i], failed[i+1:]...)
				i--
			}
		}
	} else {
		for _, r := range results {
			if !r.Connected {
				if _, seen := failedSet[r.Raw]; !seen {
					failedSet[r.Raw] = struct{}{}
					failed = append(failed, r.Raw)
				}
			}
		}
	}

	if opt.OutputFile != "" {
		_ = os.WriteFile(opt.OutputFile, []byte(strings.Join(valid, "\n")+endIfAny(valid)), 0o644)
	}
	if opt.FailedFile != "" {
		_ = os.WriteFile(opt.FailedFile, []byte(strings.Join(failed, "\n")+endIfAny(failed)), 0o644)
	}
	if opt.JSONFile != "" {
		b, _ := json.MarshalIndent(results, "", "  ")
		_ = os.WriteFile(opt.JSONFile, b, 0o644)
	}
}

func endIfAny(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return "\n"
}
