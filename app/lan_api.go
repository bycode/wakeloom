package main

// LAN OpenAI endpoint: one chosen local IPv4 address and port.
// It serves GET /v1/models, GET /v1/models/{id} and POST /v1/chat/completions,
// then forwards them to the current session's /wbllm route.
// The workbench, wake/stop and every other path stay off this listener.

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	lanKeySentinel = "********"
	lanKeyMin      = 16
)

type lanIface struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
}

type lanRuntime struct {
	mu   sync.Mutex
	srv  *http.Server
	addr string
	err  string
}

var lanRT lanRuntime

// lanForward is the hop to the Colab session. Tests replace it.
var lanForward = forwardLanAPI

var lanClient = sync.OnceValue(func() *http.Client {
	t := transport.Clone()
	t.ResponseHeaderTimeout = 0
	return &http.Client{
		Transport: t,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
})

func localIPv4s() []lanIface {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []lanIface
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			out = append(out, lanIface{Name: ifi.Name, Addr: ip4.String()})
		}
	}
	return out
}

func lanAddrAllowed(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil || parsed.To4() == nil || parsed.IsUnspecified() || parsed.IsMulticast() {
		return false
	}
	want := parsed.To4().String()
	for _, it := range localIPv4s() {
		if it.Addr == want {
			return true
		}
	}
	return false
}

func validateLanAPI(c Config) error {
	if !c.LanAPIEnabled {
		return nil
	}
	c.LanAPIAddr = strings.TrimSpace(c.LanAPIAddr)
	if !lanAddrAllowed(c.LanAPIAddr) {
		return errors.New("请选择当前插在这台电脑上的网卡地址")
	}
	if c.LanAPIPort < 1 || c.LanAPIPort > 65535 {
		return errors.New("端口要在 1 到 65535 之间")
	}
	key := strings.TrimSpace(c.LanAPIKey)
	if len(key) < lanKeyMin {
		return fmt.Errorf("接口密钥至少 %d 个字符", lanKeyMin)
	}
	if strings.ContainsAny(key, " \t\r\n") {
		return errors.New("接口密钥不能包含空格")
	}
	return nil
}

// lanAPIApply starts or stops the listener for c. The caller stores c first
// when the listener should use that config. A failed bind leaves the previous
// listener running.
func lanAPIApply(c Config) error {
	lanRT.mu.Lock()
	defer lanRT.mu.Unlock()
	if !c.LanAPIEnabled {
		lanStopLocked()
		lanRT.err = ""
		return nil
	}
	if err := validateLanAPI(c); err != nil {
		return err
	}
	addr := net.JoinHostPort(strings.TrimSpace(c.LanAPIAddr), strconv.Itoa(c.LanAPIPort))
	if lanRT.srv != nil && lanRT.addr == addr {
		lanRT.err = ""
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		msg := "无法监听 " + addr + "：" + err.Error()
		if lanRT.srv == nil {
			lanRT.err = msg
		}
		return errors.New(msg)
	}
	lanStopLocked()
	srv := &http.Server{
		Handler:           lanHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
	lanRT.srv = srv
	lanRT.addr = ln.Addr().String()
	lanRT.err = ""
	go func() {
		err := srv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			diagEvent("error", "lan", "内网接口停止："+err.Error())
			lanRT.mu.Lock()
			if lanRT.srv == srv {
				lanRT.srv = nil
				lanRT.addr = ""
				lanRT.err = "内网接口停止：" + err.Error()
			}
			lanRT.mu.Unlock()
		}
	}()
	diagEvent("info", "lan", "内网 OpenAI 接口监听 "+lanRT.addr)
	return nil
}

func lanStopLocked() {
	if lanRT.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = lanRT.srv.Shutdown(ctx)
		cancel()
		lanRT.srv = nil
	}
	lanRT.addr = ""
}

func lanAPIStatus() map[string]any {
	lanRT.mu.Lock()
	defer lanRT.mu.Unlock()
	c := getConfig()
	base := ""
	if lanRT.addr != "" {
		base = "http://" + lanRT.addr + "/v1"
	}
	return map[string]any{
		"enabled":   c.LanAPIEnabled,
		"listening": lanRT.addr != "",
		"addr":      lanRT.addr,
		"base":      base,
		"error":     lanRT.err,
	}
}

func lanHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := getConfig()
		if !c.LanAPIEnabled {
			lanWriteErr(w, 503, "内网接口未启用")
			return
		}
		if !lanAuthed(r, c.LanAPIKey) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			lanWriteErr(w, 401, "密钥不正确")
			return
		}
		p := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/"))
		tail, ok := lanTail(p, r.Method)
		if !ok {
			lanWriteErr(w, 404, "只提供 GET /v1/models 和 POST /v1/chat/completions")
			return
		}
		if baseURL() == "" {
			lanWriteErr(w, 503, "还没有连接网关或本地 Colab")
			return
		}
		var body []byte
		if r.Method == http.MethodPost {
			var err error
			body, err = io.ReadAll(io.LimitReader(r.Body, 8<<20+1))
			if err != nil {
				lanWriteErr(w, 400, "无法读取请求")
				return
			}
			if len(body) > 8<<20 {
				lanWriteErr(w, 413, "请求超过 8 MB")
				return
			}
		}
		resp, err := lanForward(r, tail, body)
		if err != nil {
			lanWriteErr(w, 502, "连不上 GPU 上的模型")
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			lanWriteErr(w, 502, "连不上 GPU 上的模型")
			return
		}
		if resp.StatusCode >= 400 {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			lanWriteErr(w, resp.StatusCode, lanUpstreamMessage(raw))
			return
		}
		if ct := resp.Header.Get("Content-Type"); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(resp.StatusCode)
		fl, _ := w.(http.Flusher)
		buf := make([]byte, 32<<10)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				if fl != nil {
					fl.Flush()
				}
			}
			if err != nil {
				return
			}
		}
	})
}

func lanAuthed(r *http.Request, key string) bool {
	key = strings.TrimSpace(key)
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(key) < lanKeyMin || len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		return false
	}
	got := h[7:]
	if len(got) != len(key) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(key)) == 1
}

func lanTail(p, method string) (string, bool) {
	switch p {
	case "/v1/models":
		return "v1/models", method == http.MethodGet
	case "/v1/chat/completions":
		return "v1/chat/completions", method == http.MethodPost
	}
	const model = "/v1/models/"
	if strings.HasPrefix(p, model) && method == http.MethodGet {
		id := p[len(model):]
		if id == "" || strings.ContainsAny(id, "/\\?#") || strings.Contains(id, "..") {
			return "", false
		}
		return "v1/models/" + id, true
	}
	return "", false
}

func forwardLanAPI(r *http.Request, tail string, body []byte) (*http.Response, error) {
	b := baseURL()
	if b == "" {
		return nil, errors.New("no upstream")
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, b+"/wbllm/"+tail, rd)
	if err != nil {
		return nil, err
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	} else if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if accept := r.Header.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	}
	addAuth(req)
	return lanClient().Do(req)
}

func lanUpstreamMessage(raw []byte) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) == nil {
		errS, _ := m["error"].(string)
		msg, _ := m["message"].(string)
		if strings.Contains(strings.ToLower(errS+" "+msg), "not allowed") {
			return "当前启动配置没有 OpenAI 兼容接口。Qwen 1M 只接受软件内部的对话路径，请改用普通 Ollama 对话配置。"
		}
		if errS == "asleep" || strings.Contains(msg, "未就绪") {
			return "GPU 未就绪"
		}
		if strings.TrimSpace(msg) != "" {
			return msg
		}
		if strings.TrimSpace(errS) != "" {
			return errS
		}
	}
	return "GPU 上的模型拒绝了这个请求"
}

func lanWriteErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"message": msg, "type": "server_error"},
	})
}
