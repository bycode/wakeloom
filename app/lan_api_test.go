package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLanAPIValidation(t *testing.T) {
	if !lanAddrAllowed("127.0.0.1") {
		t.Fatal("127.0.0.1 should be a local address")
	}
	if lanAddrAllowed("0.0.0.0") || lanAddrAllowed("8.8.8.8") || lanAddrAllowed("224.0.0.1") {
		t.Fatal("rejected addresses were accepted")
	}
	ok := Config{LanAPIEnabled: true, LanAPIAddr: "127.0.0.1", LanAPIPort: 9, LanAPIKey: "0123456789abcdef"}
	if err := validateLanAPI(ok); err != nil {
		t.Fatal(err)
	}
	for _, c := range []Config{
		{LanAPIEnabled: true, LanAPIAddr: "0.0.0.0", LanAPIPort: 9, LanAPIKey: ok.LanAPIKey},
		{LanAPIEnabled: true, LanAPIAddr: "8.8.8.8", LanAPIPort: 9, LanAPIKey: ok.LanAPIKey},
		{LanAPIEnabled: true, LanAPIAddr: "127.0.0.1", LanAPIPort: 0, LanAPIKey: ok.LanAPIKey},
		{LanAPIEnabled: true, LanAPIAddr: "127.0.0.1", LanAPIPort: 9, LanAPIKey: "short"},
		{LanAPIEnabled: true, LanAPIAddr: "127.0.0.1", LanAPIPort: 9, LanAPIKey: "0123456789abc def"},
	} {
		if err := validateLanAPI(c); err == nil {
			t.Fatalf("accepted %#v", c)
		}
	}
	if err := validateLanAPI(Config{LanAPIEnabled: false, LanAPIAddr: "8.8.8.8"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := lanTail("/_gate/wake", "POST"); ok {
		t.Fatal("control path allowed")
	}
	if _, ok := lanTail("/wbllm/api/chat", "POST"); ok {
		t.Fatal("raw wbllm path allowed")
	}
	if tail, ok := lanTail("/v1/models/qwen", "GET"); !ok || tail != "v1/models/qwen" {
		t.Fatalf("model id: %q %v", tail, ok)
	}
	if _, ok := lanTail("/v1/models/a/b", "GET"); ok {
		t.Fatal("nested model id allowed")
	}
}

func TestLanAPIListenProxyAndStop(t *testing.T) {
	withTempConfig(t, Config{})
	orig := lanForward
	t.Cleanup(func() {
		lanForward = orig
		_ = lanAPIApply(Config{})
	})
	var gotTail, gotAuth, gotBody string
	lanForward = func(r *http.Request, tail string, body []byte) (*http.Response, error) {
		gotTail, gotAuth, gotBody = tail, r.Header.Get("Authorization"), string(body)
		switch tail {
		case "v1/models":
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"object":"list"}`))}, nil
		case "v1/chat/completions":
			pr, pw := io.Pipe()
			go func() {
				_, _ = pw.Write([]byte("data: one\n\n"))
				time.Sleep(40 * time.Millisecond)
				_, _ = pw.Write([]byte("data: two\n\n"))
				_ = pw.Close()
			}()
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: pr}, nil
		default:
			t.Errorf("unexpected tail %s", tail)
			return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader(`{"error":"x"}`))}, nil
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	key := "0123456789abcdef"
	c := Config{LanAPIEnabled: true, LanAPIAddr: "127.0.0.1", LanAPIPort: port, LanAPIKey: key, GateURL: "https://gate.example"}
	cfgMu.Lock()
	cfg = c
	cfgMu.Unlock()
	if err := lanAPIApply(c); err != nil {
		t.Fatal(err)
	}
	base := "http://" + lanRT.addr
	client := &http.Client{Timeout: 3 * time.Second}

	res, err := client.Get(base + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 401 {
		t.Fatalf("missing key: %d", res.StatusCode)
	}
	res.Body.Close()

	req, _ := http.NewRequest(http.MethodGet, base+"/v1/models?key="+key, nil)
	res, err = client.Do(req)
	if err != nil || res.StatusCode != 401 {
		t.Fatalf("query key must not authenticate: %v", res)
	}
	res.Body.Close()

	req, _ = http.NewRequest(http.MethodPost, base+"/_gate/wake", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+key)
	res, err = client.Do(req)
	if err != nil || res.StatusCode != 404 {
		t.Fatalf("control path: %v %v", err, res)
	}
	res.Body.Close()

	req, _ = http.NewRequest(http.MethodGet, base+"/v1/../_gate/wake", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	res, err = client.Do(req)
	if err != nil || res.StatusCode != 404 {
		t.Fatalf("cleaned control path: %v %v", err, res)
	}
	res.Body.Close()

	req, _ = http.NewRequest(http.MethodGet, base+"/api/config", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	res, err = client.Do(req)
	if err != nil || res.StatusCode != 404 {
		t.Fatalf("workbench path: %v %v", err, res)
	}
	res.Body.Close()

	req, _ = http.NewRequest(http.MethodGet, base+"/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(b), `"list"`) || gotTail != "v1/models" {
		t.Fatalf("models: %d %s tail=%s", res.StatusCode, b, gotTail)
	}
	if gotAuth != "Bearer "+key {
		t.Fatalf("listener did not see the client key: %q", gotAuth)
	}

	req, _ = http.NewRequest(http.MethodPost, base+"/v1/chat/completions", strings.NewReader(`{"stream":true}`))
	req.Header.Set("Authorization", "Bearer "+key)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	first := make([]byte, 10)
	n, err := io.ReadFull(res.Body, first)
	if err != nil || string(first[:n]) != "data: one\n" {
		t.Fatalf("first chunk %q %v", first[:n], err)
	}
	rest, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(rest), "data: two") || gotBody != `{"stream":true}` {
		t.Fatalf("rest %q body %q", rest, gotBody)
	}

	lanForward = func(r *http.Request, tail string, body []byte) (*http.Response, error) {
		if tail == "v1/models" {
			return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader(`{"error":"asleep","message":"GPU 未就绪"}`))}, nil
		}
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(`{"error":"not allowed"}`))}, nil
	}
	req, _ = http.NewRequest(http.MethodGet, base+"/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 503 || !strings.Contains(string(b), "GPU 未就绪") || strings.Contains(string(b), "asleep") {
		t.Fatalf("asleep rewrite: %d %s", res.StatusCode, b)
	}
	req, _ = http.NewRequest(http.MethodPost, base+"/v1/chat/completions", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+key)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 404 || !strings.Contains(string(b), "Qwen 1M") {
		t.Fatalf("1M rewrite: %d %s", res.StatusCode, b)
	}

	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	bad := c
	bad.LanAPIPort = busy.Addr().(*net.TCPAddr).Port
	if err := lanAPIApply(bad); err == nil {
		t.Fatal("occupied port was accepted")
	}
	if st := lanAPIStatus(); !st["listening"].(bool) || st["addr"] != strings.TrimPrefix(base, "http://") {
		t.Fatalf("old listener lost: %#v", st)
	}

	if err := lanAPIApply(Config{LanAPIKey: key}); err != nil {
		t.Fatal(err)
	}
	if st := lanAPIStatus(); st["listening"].(bool) {
		t.Fatalf("still listening: %#v", st)
	}
	if _, err := client.Get(base + "/v1/models"); err == nil {
		t.Fatal("disabled listener still accepted a connection")
	}
}

func TestForwardLanAPIUsesSessionAuth(t *testing.T) {
	var gotAuth, gotPath string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"object":"list"}`))
	}))
	defer up.Close()
	withTempConfig(t, Config{Mode: "gateway", GateURL: up.URL, Token: "gate-token-value"})
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer 0123456789abcdef")
	resp, err := forwardLanAPI(req, "v1/models", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || gotPath != "/wbllm/v1/models" || gotAuth != "Bearer gate-token-value" {
		t.Fatalf("upstream auth/path: %d %s %s", resp.StatusCode, gotPath, gotAuth)
	}
}

func TestLanAPIConfigRoundTrip(t *testing.T) {
	key := "fedcba9876543210"
	withTempConfig(t, Config{LanAPIKey: key, LanAPIAddr: "127.0.0.1", LanAPIPort: 9, Onboarded: true})
	t.Cleanup(func() { _ = lanAPIApply(Config{}) })
	srv := newServer()
	call := func(method, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "/api/config", strings.NewReader(body))
		req.Header.Set("X-Key", apiKey)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		return w
	}
	w := call("GET", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), lanKeySentinel) || strings.Contains(w.Body.String(), key) {
		t.Fatalf("mask: %d %s", w.Code, w.Body.String())
	}
	w = call("POST", `{"lan_api_enabled":false,"lan_api_addr":"127.0.0.1","lan_api_port":9,"lan_api_key":"********","onboarded":false}`)
	if w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	if getConfig().LanAPIKey != key || !getConfig().Onboarded {
		t.Fatalf("restore: %+v", getConfig())
	}
	w = call("POST", `{"lan_api_enabled":true,"lan_api_addr":"8.8.8.8","lan_api_port":9,"lan_api_key":"0123456789abcdef"}`)
	if w.Code != 400 || getConfig().LanAPIAddr == "8.8.8.8" {
		t.Fatalf("bad addr persisted: %d %+v %s", w.Code, getConfig(), w.Body.String())
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	w = call("POST", `{"lan_api_enabled":true,"lan_api_addr":"127.0.0.1","lan_api_port":`+strconv.Itoa(port)+`,"lan_api_key":"`+key+`"}`)
	if w.Code != 200 || !lanAPIStatus()["listening"].(bool) {
		t.Fatalf("enable: %d %s %#v", w.Code, w.Body.String(), lanAPIStatus())
	}
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	w = call("POST", `{"lan_api_enabled":true,"lan_api_addr":"127.0.0.1","lan_api_port":`+strconv.Itoa(busy.Addr().(*net.TCPAddr).Port)+`,"lan_api_key":"`+key+`"}`)
	if w.Code != 400 || getConfig().LanAPIPort != port || !lanAPIStatus()["listening"].(bool) {
		t.Fatalf("busy bind changed config: %d port=%d %#v %s", w.Code, getConfig().LanAPIPort, lanAPIStatus(), w.Body.String())
	}
}
