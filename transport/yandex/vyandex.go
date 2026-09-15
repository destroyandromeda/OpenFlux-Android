package yandex

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"universal-bypass-tool/transport"
	"universal-bypass-tool/utils"
)

type VolgaConfig struct {
	MaxIdleConnsPerHost int
	MaxIdleConns        int
	IdleConnTimeout     time.Duration
	RelayTimeout        time.Duration

	WorkerCount int
	QueueSize   int

	BatchSize     int
	BatchTimeout  time.Duration
	BatchMaxBytes int

	MaxPayloadBytes int
	MinPayloadBytes int

	ReconnectMinDelay   time.Duration
	ReconnectMaxDelay   time.Duration
	ReconnectMultiplier float64

	WSHandshakeTimeout time.Duration
	WSReadTimeout      time.Duration
	KeepAliveInterval  time.Duration
}

func DefaultVolgaConfig() VolgaConfig {
	return VolgaConfig{
		MaxIdleConnsPerHost: 2000,
		MaxIdleConns:        4000,
		IdleConnTimeout:     90 * time.Second,
		RelayTimeout:        30 * time.Second,

		WorkerCount: 2000,
		QueueSize:   8192,

		BatchSize:     20,
		BatchTimeout:  2 * time.Millisecond,
		BatchMaxBytes: 4 * 1024 * 1024,

		MaxPayloadBytes: 5_000_000,
		MinPayloadBytes: 200,

		ReconnectMinDelay:   500 * time.Millisecond,
		ReconnectMaxDelay:   30 * time.Second,
		ReconnectMultiplier: 1.5,

		WSHandshakeTimeout: 10 * time.Second,
		WSReadTimeout:      60 * time.Second,
		KeepAliveInterval:  10 * time.Second,
	}
}

const volgaUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:153.0) Gecko/20100101 Firefox/153.0"

var reClientConfig = regexp.MustCompile(`<script[^>]*id="client-config"[^>]*>(.*?)</script>`)

var (
	b64BufPool = sync.Pool{
		New: func() interface{} { return make([]byte, 0, 16*1024*1024) },
	}
	jsonBufPool = sync.Pool{
		New: func() interface{} { return bytes.NewBuffer(make([]byte, 0, 128*1024)) },
	}
	blobBufPool = sync.Pool{
		New: func() interface{} { return bytes.NewBuffer(make([]byte, 0, 64*1024)) },
	}
)

func base64Encode(data []byte) string {
	buf := b64BufPool.Get().([]byte)
	need := base64.StdEncoding.EncodedLen(len(data))
	if cap(buf) < need {
		buf = make([]byte, need)
	} else {
		buf = buf[:need]
	}
	base64.StdEncoding.Encode(buf, data)
	out := string(buf)
	b64BufPool.Put(buf[:0])
	return out
}

type VolgaStats struct {
	PacketsSent     atomic.Uint64
	PacketsRecv     atomic.Uint64
	BytesSent       atomic.Uint64
	BytesReceived   atomic.Uint64
	HTTPReqsSent    atomic.Uint64
	HTTPReqsFailed  atomic.Uint64
	WSReconnects    atomic.Uint64
	QueueDrops      atomic.Uint64
	WorkerBusy      atomic.Int64
	BatchesSent     atomic.Uint64
	PacketsBatched  atomic.Uint64
	OutOfOrder      atomic.Uint64
	Duplicates      atomic.Uint64
	GapsSkipped     atomic.Uint64
	LastHTTPSuccess atomic.Int64
}

type volgaAuth struct {
	Session     *http.Client
	AccessToken string
	Token       string
	RequestPath string
	ResourceURL string
	DocID       string
	UserID      int
	UserIDStr   string
	Sign        string
	TS          string
	SessionID   string
	Cookies     []*http.Cookie
	TokenTTL    int64
}

func authorize(docURL string) (*volgaAuth, error) {
	utils.Debugf("[VOLGA] authorize(%s)", docURL)

	jar, _ := cookiejar.New(nil)
	session := &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var finalBody []byte
	var finalURL string
	currentURL := docURL

	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest("GET", currentURL, nil)
		req.Header.Set("User-Agent", volgaUserAgent)
		req.Header.Set("Accept-Language", "ru-RU,ru;q=0.9")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		if i > 0 {
			req.Header.Set("Referer", docURL)
		}

		resp, err := session.Do(req)
		if err != nil {
			return nil, fmt.Errorf("GET %s: %w", currentURL, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		utils.Debugf("[VOLGA] GET %s -> %d (%d bytes)", currentURL, resp.StatusCode, len(body))

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			if loc == "" {
				return nil, fmt.Errorf("redirect without Location from %s", currentURL)
			}
			if strings.HasPrefix(loc, "/") {
				u, _ := url.Parse(currentURL)
				loc = u.Scheme + "://" + u.Host + loc
			}
			currentURL = loc
			continue
		}

		finalBody = body
		finalURL = currentURL
		break
	}

	if finalBody == nil {
		return nil, fmt.Errorf("too many redirects from %s", docURL)
	}

	utils.Debugf("[VOLGA] final URL: %s", finalURL)

	m := reClientConfig.FindSubmatch(finalBody)
	if len(m) < 2 {
		preview := string(finalBody)
		if len(preview) > 3000 {
			preview = preview[:3000]
		}
		utils.Debugf("[VOLGA] HTML preview: %s", preview)
		return nil, fmt.Errorf("client-config not found in %s", finalURL)
	}

	var cfg map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(m[1]))
	dec.UseNumber()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse client-config: %w", err)
	}

	utils.Debugf("[VOLGA] client-config keys: %v", mapKeys(cfg))

	office, _ := cfg["officeActionData"].(map[string]interface{})
	editor, _ := cfg["editorParams"].(map[string]interface{})

	if office == nil {
		return nil, fmt.Errorf("officeActionData missing (keys: %v)", mapKeys(cfg))
	}

	utils.Debugf("[VOLGA] office keys: %v", mapKeys(office))

	actionURL := getStr(office, "action_url")
	accessToken := getStr(office, "access_token")
	ttl := office["access_token_ttl"]

	utils.Debugf("[VOLGA] action_url: %s", actionURL)
	utils.Debugf("[VOLGA] access_token: %d bytes", len(accessToken))
	utils.Debugf("[VOLGA] access_token_ttl: %v (%T)", ttl, ttl)
	var ttlInt int64
	switch v := ttl.(type) {
	case json.Number:
		if parsed, err := v.Int64(); err == nil {
			ttlInt = parsed
		}
	case float64:
		ttlInt = int64(v)
	case int64:
		ttlInt = v
	}
	if ttlInt > 0 {
		ttlInt /= 1000
	}

	a := &volgaAuth{
		Session:     session,
		AccessToken: accessToken,
		ResourceURL: getStr(office, "resource_url"),
		DocID:       getStr(editor, "idDoc"),
		TokenTTL:    ttlInt,
	}

	if actionURL == "" {
		return nil, fmt.Errorf("action_url missing (keys: %v)", mapKeys(office))
	}
	if a.AccessToken == "" {
		return nil, fmt.Errorf("access_token missing")
	}

	ttlStr := formatTTL(ttl)
	utils.Debugf("[VOLGA] ttl formatted: %q", ttlStr)

	form := url.Values{}
	form.Set("access_token", a.AccessToken)
	form.Set("access_token_ttl", ttlStr)
	body := form.Encode()

	utils.Debugf("[VOLGA] POST %s (body %d bytes)", actionURL, len(body))

	req2, _ := http.NewRequest("POST", actionURL, strings.NewReader(body))
	req2.Header.Set("User-Agent", volgaUserAgent)
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Origin", "https://disk.yandex.ru")
	req2.Header.Set("Referer", finalURL)
	req2.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req2.Header.Set("Accept-Language", "ru-RU,ru;q=0.9")
	req2.Header.Set("Upgrade-Insecure-Requests", "1")
	req2.Header.Set("Sec-Fetch-Dest", "iframe")
	req2.Header.Set("Sec-Fetch-Mode", "navigate")
	req2.Header.Set("Sec-Fetch-Site", "cross-site")

	resp2, err := session.Do(req2)
	if err != nil {
		return nil, fmt.Errorf("POST auth/initial: %w", err)
	}
	resp2.Body.Close()

	utils.Debugf("[VOLGA] auth/initial -> %d", resp2.StatusCode)

	if resp2.StatusCode != 302 {
		return nil, fmt.Errorf("auth/initial status %d (expected 302)", resp2.StatusCode)
	}

	location := resp2.Header.Get("Location")
	if location == "" {
		return nil, fmt.Errorf("auth/initial no Location")
	}

	utils.Debugf("[VOLGA] Location: %s", location[:minInt(len(location), 300)])

	if strings.Contains(location, "/document/error/") {
		return nil, fmt.Errorf("auth/initial returned /document/error/ - check access_token_ttl and Referer")
	}

	locParsed, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("parse Location: %w", err)
	}
	qs := locParsed.Query()

	a.Token = qs.Get("token")
	a.RequestPath = qs.Get("request-path")

	jsonStr := qs.Get("json")
	if jsonStr == "" {
		return nil, fmt.Errorf("no json in Location (token=%v rp=%v)",
			a.Token != "", a.RequestPath != "")
	}

	var jsonData map[string]interface{}
	dec2 := json.NewDecoder(strings.NewReader(jsonStr))
	dec2.UseNumber()
	if err := dec2.Decode(&jsonData); err != nil {
		return nil, fmt.Errorf("parse Location json: %w", err)
	}

	a.SessionID = getStr(jsonData, "sessionId")
	a.UserID = int(getFloat(jsonData, "userId"))

	if xiva, ok := jsonData["xiva"].(map[string]interface{}); ok {
		a.Sign = getStr(xiva, "sign")
		a.TS = getStr(xiva, "ts")
		a.UserIDStr = getStr(xiva, "user")
	}

	req3, _ := http.NewRequest("GET", location, nil)
	req3.Header.Set("User-Agent", volgaUserAgent)
	req3.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req3.Header.Set("Referer", actionURL)
	resp3, err := session.Do(req3)
	if err != nil {
		return nil, fmt.Errorf("GET Location: %w", err)
	}
	io.Copy(io.Discard, resp3.Body)
	resp3.Body.Close()

	a.Cookies = jar.Cookies(locParsed)

	if a.Token == "" || a.RequestPath == "" || a.UserIDStr == "" || a.Sign == "" {
		return nil, fmt.Errorf("incomplete auth: token=%v rp=%v user=%v sign=%v",
			a.Token != "", a.RequestPath != "", a.UserIDStr != "", a.Sign != "")
	}

	utils.Debugf("[VOLGA] auth OK: user=%d(%s) rp=%s sign=%s ts=%s",
		a.UserID, a.UserIDStr, a.RequestPath, a.Sign, a.TS)
	return a, nil
}

func getStr(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int64:
		return strconv.FormatInt(v, 10)
	case int:
		return strconv.Itoa(v)
	}
	return ""
}

func getFloat(m map[string]interface{}, key string) float64 {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return v
	case json.Number:
		f, _ := v.Float64()
		return f
	case int64:
		return float64(v)
	case int:
		return float64(v)
	case string:
		f, _ := strconv.ParseFloat(v, 64)
		return f
	}
	return 0
}

func formatTTL(v interface{}) string {
	switch x := v.(type) {
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatInt(int64(x), 10)
	case int64:
		return strconv.FormatInt(x, 10)
	case int:
		return strconv.Itoa(x)
	case string:
		return x
	case nil:
		return "0"
	default:
		return fmt.Sprintf("%v", x)
	}
}

func mapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var sequencedBatchMagic = [4]byte{'O', 'F', 'B', 1}

type relayBatch struct {
	sequence uint64
	packets  [][]byte
}

type relayClient struct {
	auth   *volgaAuth
	config VolgaConfig
	stats  *VolgaStats

	httpClients []*http.Client
	workers     int
	queue       chan []byte
	batchQueue  chan relayBatch
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc

	bundleID atomic.Uint64
	seq      atomic.Uint64
	localID  atomic.Uint64
	batchSeq atomic.Uint64
	epoch    uint64

	mu       sync.Mutex
	frontier string
}

func newRelayClient(auth *volgaAuth, cfg VolgaConfig, stats *VolgaStats) *relayClient {
	ctx, cancel := context.WithCancel(context.Background())
	var epochBytes [8]byte
	if _, err := cryptorand.Read(epochBytes[:]); err != nil {
		binary.BigEndian.PutUint64(epochBytes[:], uint64(time.Now().UnixNano()))
	}
	epoch := binary.BigEndian.Uint64(epochBytes[:])
	if epoch == 0 {
		epoch = 1
	}
	stats.LastHTTPSuccess.Store(time.Now().UnixNano())
	const connectionCount = 1
	httpClients := make([]*http.Client, connectionCount)
	for i := range httpClients {
		tr := &http.Transport{
			MaxIdleConns:        cfg.MaxIdleConns,
			MaxIdleConnsPerHost: cfg.MaxIdleConnsPerHost,
			IdleConnTimeout:     cfg.IdleConnTimeout,
			DisableCompression:  true,
			ForceAttemptHTTP2:   true,
		}
		httpClients[i] = &http.Client{
			Transport: tr,
			Timeout:   cfg.RelayTimeout,
			Jar:       auth.Session.Jar,
		}
	}

	return &relayClient{
		auth:        auth,
		config:      cfg,
		stats:       stats,
		httpClients: httpClients,
		epoch:       epoch,
		workers:     cfg.WorkerCount,
		queue:       make(chan []byte, cfg.QueueSize),
		batchQueue:  make(chan relayBatch, cfg.WorkerCount*4),
		ctx:         ctx,
		cancel:      cancel,
	}
}

func (r *relayClient) Start() {
	r.wg.Add(1)
	go r.batcher()
	for i := 0; i < r.workers; i++ {
		r.wg.Add(1)
		go r.worker(i)
	}
	utils.Debugf("[VOLGA] relay pool started: %d workers, batch=%d timeout=%v",
		r.workers, r.config.BatchSize, r.config.BatchTimeout)
}

func (r *relayClient) Stop() {
	r.cancel()
	r.wg.Wait()
	for _, client := range r.httpClients {
		client.CloseIdleConnections()
	}
}

func (r *relayClient) Send(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if len(data) > r.config.MaxPayloadBytes {
		return fmt.Errorf("packet too large: %d > %d", len(data), r.config.MaxPayloadBytes)
	}

	cp := make([]byte, len(data))
	copy(cp, data)

	select {
	case <-r.ctx.Done():
		return r.ctx.Err()
	case r.queue <- cp:
		return nil
	default:
		r.stats.QueueDrops.Add(1)
		return fmt.Errorf("queue full")
	}
}

func (r *relayClient) batcher() {
	defer r.wg.Done()

	batch := make([][]byte, 0, r.config.BatchSize)
	totalBytes := 0
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()

	resetTimer := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(r.config.BatchTimeout)
	}

	flush := func() bool {
		if len(batch) == 0 {
			return true
		}
		ready := relayBatch{sequence: r.batchSeq.Add(1), packets: batch}
		batch = make([][]byte, 0, r.config.BatchSize)
		totalBytes = 0
		select {
		case r.batchQueue <- ready:
			return true
		case <-r.ctx.Done():
			return false
		}
	}

	for {
		select {
		case <-r.ctx.Done():
			return

		case pkt := <-r.queue:
			batch = append(batch, pkt)
			totalBytes += len(pkt)

			if len(batch) >= r.config.BatchSize || totalBytes >= r.config.BatchMaxBytes {
				if !flush() {
					return
				}
			} else if len(batch) == 1 {
				resetTimer()
			}

		case <-timer.C:
			if !flush() {
				return
			}
		}
	}
}

func (r *relayClient) worker(id int) {
	defer r.wg.Done()
	for {
		select {
		case <-r.ctx.Done():
			return
		case batch := <-r.batchQueue:
			r.stats.WorkerBusy.Add(1)
			err := r.sendBatchWithRetry(batch, id)
			if err != nil && !errors.Is(err, context.Canceled) {
				r.stats.HTTPReqsFailed.Add(1)
				utils.Debugf("[VOLGA] batch send failed: %v", err)
			} else if err == nil {
				r.stats.HTTPReqsSent.Add(1)
				r.stats.BatchesSent.Add(1)
			}
			r.stats.WorkerBusy.Add(-1)
		}
	}
}

func (r *relayClient) sendBatch(batch relayBatch, connection int) error {
	blob := blobBufPool.Get().(*bytes.Buffer)
	blob.Reset()
	blob.Write(sequencedBatchMagic[:])
	var sequenceHeader [16]byte
	binary.BigEndian.PutUint64(sequenceHeader[:8], r.epoch)
	binary.BigEndian.PutUint64(sequenceHeader[8:], batch.sequence)
	blob.Write(sequenceHeader[:])

	var lenBuf [2]byte
	var totalBytes int
	for _, p := range batch.packets {
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(p)))
		blob.Write(lenBuf[:])
		blob.Write(p)
		totalBytes += len(p)
	}

	encoded := base64Encode(blob.Bytes())
	blobBufPool.Put(blob)

	frontier := r.getFrontier()
	opID := fmt.Sprintf("1-%d.%d", r.auth.UserID, r.seq.Add(1))
	relayOpID := fmt.Sprintf("1-%d.%d", r.auth.UserID, r.seq.Add(1))

	bundle := []interface{}{
		map[string]interface{}{
			"id":         opID,
			"frontier":   frontier,
			"undoable":   true,
			"actionName": "textInsert",
			"ops":        []interface{}{[]interface{}{"it", "vyd:t/00000000000008", 0, "A"}},
			"sideEffect": false,
			"localId":    r.localID.Add(1),
		},
		map[string]interface{}{
			"id":         relayOpID,
			"frontier":   []interface{}{opID},
			"undoable":   false,
			"actionName": "setCaret",
			"ops": []interface{}{
				[]interface{}{"us", r.auth.UserID, []interface{}{
					[]interface{}{
						[]interface{}{"vyd:t/00000000000008", 0, -1},
						[]interface{}{"vyd:t/00000000000008", 0, -1},
					},
				}},
			},
			"sideEffect": true,
			"localId":    r.localID.Add(1),
		},
		encoded,
	}

	payload := map[string]interface{}{
		"message": map[string]interface{}{
			"bundleId": r.bundleID.Add(1),
			"bundle":   bundle,
		},
		"targetUserId": nil,
	}

	buf := jsonBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		jsonBufPool.Put(buf)
		return err
	}
	bodyCopy := make([]byte, buf.Len())
	copy(bodyCopy, buf.Bytes())
	jsonBufPool.Put(buf)

	urlStr := fmt.Sprintf("https://volga.yandex.ru/session/main/%s/relay", r.auth.RequestPath)
	req, err := http.NewRequestWithContext(r.ctx, "POST", urlStr, bytes.NewReader(bodyCopy))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", volgaUserAgent)
	req.Header.Set("Authorization", "Bearer "+r.auth.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://volga.yandex.ru")
	req.Header.Set("Referer", "https://volga.yandex.ru/document/?request-path="+r.auth.RequestPath)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.ContentLength = int64(len(bodyCopy))

	var cookieParts []string
	for _, c := range r.auth.Cookies {
		cookieParts = append(cookieParts, c.Name+"="+c.Value)
	}
	if len(cookieParts) > 0 {
		req.Header.Set("Cookie", strings.Join(cookieParts, "; "))
	}

	client := r.httpClients[connection%len(r.httpClients)]
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return &relayHTTPError{status: resp.StatusCode}
	}

	r.stats.PacketsSent.Add(uint64(len(batch.packets)))
	r.stats.PacketsBatched.Add(uint64(len(batch.packets)))
	r.stats.BytesSent.Add(uint64(totalBytes))
	r.stats.LastHTTPSuccess.Store(time.Now().UnixNano())
	return nil
}

type relayHTTPError struct {
	status int
}

func (e *relayHTTPError) Error() string {
	return fmt.Sprintf("status %d", e.status)
}

func (r *relayClient) sendBatchWithRetry(batch relayBatch, connection int) error {
	const maxAttempts = 4

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := r.sendBatch(batch, connection+attempt-1)
		if err == nil {
			return nil
		}
		if attempt == maxAttempts || !isRetryableRelayError(err) {
			return err
		}

		delay := time.Duration(attempt*attempt) * 100 * time.Millisecond
		utils.Debugf("[VOLGA] transient relay error (%v), retry %d/%d in %v",
			err, attempt, maxAttempts-1, delay)
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-r.ctx.Done():
			timer.Stop()
			return r.ctx.Err()
		}
	}
	return nil
}

func isRetryableRelayError(err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	if statusErr, ok := err.(*relayHTTPError); ok {
		return statusErr.status == http.StatusRequestTimeout ||
			statusErr.status == http.StatusTooManyRequests ||
			statusErr.status >= 500
	}
	return true
}

func (r *relayClient) SetFrontier(opID string) {
	r.mu.Lock()
	r.frontier = opID
	r.mu.Unlock()
}

func (r *relayClient) getFrontier() []interface{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.frontier == "" {
		return []interface{}{}
	}
	return []interface{}{r.frontier}
}

type wsListener struct {
	auth    *volgaAuth
	config  VolgaConfig
	stats   *VolgaStats
	onData  func([]byte)
	relayMu sync.RWMutex
	relay   *relayClient

	ctx    context.Context
	cancel context.CancelFunc

	reorderMu      sync.Mutex
	receiveEpoch   uint64
	nextSequence   uint64
	pendingBatches map[uint64][][]byte
	retiredEpochs  map[uint64]struct{}
	gapTimer       *time.Timer
}

func newWSListener(auth *volgaAuth, cfg VolgaConfig, stats *VolgaStats,
	relay *relayClient, onData func([]byte)) *wsListener {

	ctx, cancel := context.WithCancel(context.Background())
	return &wsListener{
		auth:           auth,
		config:         cfg,
		stats:          stats,
		relay:          relay,
		onData:         onData,
		ctx:            ctx,
		cancel:         cancel,
		pendingBatches: make(map[uint64][][]byte),
		retiredEpochs:  make(map[uint64]struct{}),
	}
}

func (w *wsListener) Start() {
	go w.run()
}

func (w *wsListener) Stop() {
	w.cancel()
	w.reorderMu.Lock()
	if w.gapTimer != nil {
		w.gapTimer.Stop()
		w.gapTimer = nil
	}
	w.reorderMu.Unlock()
}

func (w *wsListener) SetRelay(relay *relayClient) {
	w.relayMu.Lock()
	w.relay = relay
	w.relayMu.Unlock()
}

func (w *wsListener) run() {
	delay := w.config.ReconnectMinDelay

	for {
		select {
		case <-w.ctx.Done():
			return
		default:
		}

		if err := w.connect(); err != nil {
			utils.Debugf("[VOLGA] WS error: %v", err)
		}
		if w.ctx.Err() != nil {
			return
		}

		w.stats.WSReconnects.Add(1)
		utils.Debugf("[VOLGA] WS reconnect in %v", delay)
		select {
		case <-time.After(delay):
		case <-w.ctx.Done():
			return
		}

		delay = time.Duration(float64(delay) * w.config.ReconnectMultiplier)
		if delay > w.config.ReconnectMaxDelay {
			delay = w.config.ReconnectMaxDelay
		}
	}
}

func (w *wsListener) connect() error {
	wsURL := "wss://push.yandex.ru/v2/subscribe/websocket?" +
		"service=volga" +
		"&user=" + url.QueryEscape(w.auth.UserIDStr) +
		"&sign=" + w.auth.Sign +
		"&ts=" + w.auth.TS +
		"&client=web" +
		"&session=" + w.auth.SessionID +
		"&fetch_history=" + url.QueryEscape(w.auth.UserIDStr+":volga:0:1") +
		"&x_request_attempt=0"

	header := http.Header{}
	header.Set("User-Agent", volgaUserAgent)
	header.Set("Origin", "https://volga.yandex.ru")

	var cookieParts []string
	for _, c := range w.auth.Cookies {
		cookieParts = append(cookieParts, c.Name+"="+c.Value)
	}
	header.Set("Cookie", strings.Join(cookieParts, "; "))

	dialer := websocket.Dialer{
		HandshakeTimeout: w.config.WSHandshakeTimeout,
		ReadBufferSize:   4 << 20,
		WriteBufferSize:  4 << 20,
	}

	conn, _, err := dialer.Dial(wsURL, header)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	utils.Debugf("[VOLGA] WS connected: user=%s", w.auth.UserIDStr)

	for {
		select {
		case <-w.ctx.Done():
			return nil
		default:
		}

		conn.SetReadDeadline(time.Now().Add(w.config.WSReadTimeout))
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}

		w.handleMessage(msg)
	}
}

func (w *wsListener) handleMessage(raw []byte) {
	var envelope struct {
		Operation string `json:"operation"`
		Message   string `json:"message"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return
	}

	if envelope.Operation == "ping" {
		return
	}
	if envelope.Operation != "SESSION" && envelope.Operation != "WORKER" {
		return
	}
	if envelope.Message == "" {
		return
	}

	var inner struct {
		T       string          `json:"t"`
		UserID  int             `json:"userId"`
		Bundle  json.RawMessage `json:"bundle"`
		Message json.RawMessage `json:"message"`
	}
	if err := json.Unmarshal([]byte(envelope.Message), &inner); err != nil {
		return
	}

	if inner.UserID == w.auth.UserID {
		return
	}

	switch inner.T {
	case "relay":
		w.handleRelayMessage(inner.Message)
	case "exchange":
		w.handleBundle(inner.Bundle)
	}
}

func (w *wsListener) handleRelayMessage(raw json.RawMessage) {
	var relay struct {
		Bundle []json.RawMessage `json:"bundle"`
	}
	if err := json.Unmarshal(raw, &relay); err != nil {
		return
	}
	for _, item := range relay.Bundle {
		w.handleBundleItem(item)
	}
}

func (w *wsListener) handleBundle(raw json.RawMessage) {
	var asArray []json.RawMessage
	if err := json.Unmarshal(raw, &asArray); err == nil {
		for _, item := range asArray {
			w.handleBundleItem(item)
		}
		return
	}

	var asObject struct {
		Value []json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &asObject); err == nil {
		for _, item := range asObject.Value {
			w.handleBundleItem(item)
		}
	}
}

func (w *wsListener) handleBundleItem(raw json.RawMessage) {
	var asObj struct {
		ID     string `json:"id"`
		Action string `json:"actionName"`
	}
	if err := json.Unmarshal(raw, &asObj); err == nil && asObj.Action != "" {
		if asObj.ID != "" {
			w.relayMu.RLock()
			relay := w.relay
			w.relayMu.RUnlock()
			if relay != nil {
				relay.SetFrontier(asObj.ID)
			}
		}
		return
	}

	var asStr string
	if err := json.Unmarshal(raw, &asStr); err == nil && asStr != "" {
		decoded, err := base64.StdEncoding.DecodeString(asStr)
		if err != nil {
			return
		}
		epoch, sequence, packets, sequenced := decodeSequencedBatch(decoded)
		if !sequenced {
			w.deliverPackets(decodeBatch(decoded))
			return
		}
		w.handleSequencedBatch(epoch, sequence, packets)
	}
}

func (w *wsListener) handleSequencedBatch(epoch, sequence uint64, packets [][]byte) {
	w.reorderMu.Lock()
	if _, retired := w.retiredEpochs[epoch]; retired {
		w.reorderMu.Unlock()
		return
	}
	if w.receiveEpoch != epoch {
		if w.receiveEpoch != 0 {
			w.retiredEpochs[w.receiveEpoch] = struct{}{}
		}
		w.receiveEpoch = epoch
		w.nextSequence = 1
		w.pendingBatches = make(map[uint64][][]byte)
		if w.gapTimer != nil {
			w.gapTimer.Stop()
			w.gapTimer = nil
		}
	}
	if sequence < w.nextSequence {
		w.stats.Duplicates.Add(1)
		w.reorderMu.Unlock()
		return
	}
	if _, duplicate := w.pendingBatches[sequence]; duplicate {
		w.stats.Duplicates.Add(1)
		w.reorderMu.Unlock()
		return
	}
	if sequence > w.nextSequence {
		w.stats.OutOfOrder.Add(1)
	}
	w.pendingBatches[sequence] = packets
	ready := w.collectReadyLocked()
	if len(w.pendingBatches) > 0 && w.gapTimer == nil {
		currentEpoch := w.receiveEpoch
		w.gapTimer = time.AfterFunc(500*time.Millisecond, func() {
			w.flushSequenceGap(currentEpoch)
		})
	}
	w.reorderMu.Unlock()
	w.deliverPackets(ready)
}

func (w *wsListener) collectReadyLocked() [][]byte {
	var ready [][]byte
	for {
		packets, ok := w.pendingBatches[w.nextSequence]
		if !ok {
			break
		}
		delete(w.pendingBatches, w.nextSequence)
		w.nextSequence++
		ready = append(ready, packets...)
	}
	if len(w.pendingBatches) == 0 && w.gapTimer != nil {
		w.gapTimer.Stop()
		w.gapTimer = nil
	}
	return ready
}

func (w *wsListener) flushSequenceGap(epoch uint64) {
	w.reorderMu.Lock()
	if w.receiveEpoch != epoch || len(w.pendingBatches) == 0 {
		w.gapTimer = nil
		w.reorderMu.Unlock()
		return
	}
	lowest := ^uint64(0)
	for sequence := range w.pendingBatches {
		if sequence < lowest {
			lowest = sequence
		}
	}
	if lowest > w.nextSequence {
		w.stats.GapsSkipped.Add(lowest - w.nextSequence)
	}
	w.nextSequence = lowest
	w.gapTimer = nil
	ready := w.collectReadyLocked()
	if len(w.pendingBatches) > 0 {
		currentEpoch := w.receiveEpoch
		w.gapTimer = time.AfterFunc(500*time.Millisecond, func() {
			w.flushSequenceGap(currentEpoch)
		})
	}
	w.reorderMu.Unlock()
	w.deliverPackets(ready)
}

func (w *wsListener) deliverPackets(packets [][]byte) {
	if len(packets) == 0 {
		return
	}
	w.stats.PacketsRecv.Add(uint64(len(packets)))
	for _, pkt := range packets {
		w.stats.BytesReceived.Add(uint64(len(pkt)))
		if w.onData != nil {
			w.onData(pkt)
		}
	}
}

func decodeSequencedBatch(decoded []byte) (uint64, uint64, [][]byte, bool) {
	const headerSize = 20
	if len(decoded) < headerSize || !bytes.Equal(decoded[:4], sequencedBatchMagic[:]) {
		return 0, 0, nil, false
	}
	epoch := binary.BigEndian.Uint64(decoded[4:12])
	sequence := binary.BigEndian.Uint64(decoded[12:20])
	if epoch == 0 || sequence == 0 {
		return 0, 0, nil, false
	}
	return epoch, sequence, decodeBatch(decoded[headerSize:]), true
}

func decodeBatch(decoded []byte) [][]byte {
	var packets [][]byte
	for len(decoded) >= 2 {
		ln := int(binary.BigEndian.Uint16(decoded[:2]))
		decoded = decoded[2:]
		if ln == 0 || len(decoded) < ln {
			break
		}
		packets = append(packets, decoded[:ln])
		decoded = decoded[ln:]
	}
	if len(packets) == 0 && len(decoded) > 0 {
		packets = append(packets, decoded)
	}
	return packets
}

type YandexVolgaTransport struct {
	*transport.BaseTransport

	docURL string
	config VolgaConfig
	stats  *VolgaStats

	auth      *volgaAuth
	relay     *relayClient
	ws        *wsListener
	relayMu   sync.RWMutex
	recoverMu sync.Mutex

	onDataMu sync.RWMutex
	onData   func([]byte)

	keepAliveStop chan struct{}
	tokenExpiry   int64
}

func NewYandexVolgaTransport(docURL string, cfg transport.TransportConfig) *YandexVolgaTransport {
	return &YandexVolgaTransport{
		BaseTransport: transport.NewBaseTransport(cfg),
		docURL:        docURL,
		config:        DefaultVolgaConfig(),
		stats:         &VolgaStats{},
		keepAliveStop: make(chan struct{}),
	}
}

func (t *YandexVolgaTransport) Start() error {
	if err := t.BaseTransport.Start(); err != nil {
		return err
	}

	utils.Debugf("[VOLGA] authorizing...")
	auth, err := authorize(t.docURL)
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	t.auth = auth
	t.tokenExpiry = auth.TokenTTL

	t.relay = newRelayClient(auth, t.config, t.stats)
	t.relay.Start()

	t.ws = newWSListener(auth, t.config, t.stats, t.relay, func(data []byte) {
		t.onDataMu.RLock()
		cb := t.onData
		t.onDataMu.RUnlock()
		if cb != nil {
			cb(data)
		}
		t.RecordReceive(len(data))
	})
	t.ws.Start()

	go t.keepAliveLoop()
	go t.statsLoop()
	t.SetConnected(true)

	utils.Debugf("[VOLGA] transport started: user=%d(%s) rp=%s",
		auth.UserID, auth.UserIDStr, auth.RequestPath)
	return nil
}

func (t *YandexVolgaTransport) Stop() error {
	select {
	case <-t.keepAliveStop:
	default:
		close(t.keepAliveStop)
	}
	t.recoverMu.Lock()
	t.relayMu.Lock()
	ws, relay := t.ws, t.relay
	t.ws, t.relay = nil, nil
	t.relayMu.Unlock()
	if ws != nil {
		ws.Stop()
	}
	if relay != nil {
		relay.Stop()
	}
	t.recoverMu.Unlock()
	t.SetConnected(false)
	return t.BaseTransport.Stop()
}

func (t *YandexVolgaTransport) Send(data []byte) error {
	t.relayMu.RLock()
	relay := t.relay
	t.relayMu.RUnlock()
	if relay == nil {
		return fmt.Errorf("transport not started")
	}
	return relay.Send(data)
}

func (t *YandexVolgaTransport) Receive(callback func([]byte)) {
	t.onDataMu.Lock()
	t.onData = callback
	t.onDataMu.Unlock()
}

func (t *YandexVolgaTransport) IsConnected() bool {
	return t.BaseTransport.IsConnected()
}

func (t *YandexVolgaTransport) Stats() transport.TransportStats {
	base := t.BaseTransport.Stats()
	return transport.TransportStats{
		BytesSent:     t.stats.BytesSent.Load(),
		BytesReceived: t.stats.BytesReceived.Load(),
		PacketsSent:   t.stats.PacketsSent.Load(),
		PacketsRecv:   t.stats.PacketsRecv.Load(),
		Reconnects:    t.stats.WSReconnects.Load(),
		Connected:     t.IsConnected(),
		Uptime:        base.Uptime,
	}
}

func (t *YandexVolgaTransport) keepAliveLoop() {
	ticker := time.NewTicker(t.config.KeepAliveInterval)
	defer ticker.Stop()
	var busySince time.Time

	for {
		select {
		case <-t.keepAliveStop:
			return
		case <-ticker.C:
			if !t.IsRunning() {
				return
			}
			now := time.Now()
			if t.tokenExpiry > 0 && now.Unix() > t.tokenExpiry-300 {
				utils.Debugf("[VOLGA] access token expiring, re-authorizing...")
				if err := t.recoverSession(true); err != nil {
					utils.Debugf("[VOLGA] reauthorize failed: %v", err)
				}
				continue
			}
			busy := t.stats.WorkerBusy.Load()
			if busy >= 256 {
				if busySince.IsZero() {
					busySince = now
				} else if now.Sub(busySince) >= 2*t.config.RelayTimeout {
					utils.Debugf("[VOLGA] relay saturated for %v with %d busy workers, rebuilding pool",
						now.Sub(busySince).Round(time.Second), busy)
					if err := t.recoverSession(false); err != nil {
						utils.Debugf("[VOLGA] relay pool rebuild failed: %v", err)
					}
					busySince = time.Time{}
					continue
				}
			} else {
				busySince = time.Time{}
			}
			t.relayMu.RLock()
			relay := t.relay
			t.relayMu.RUnlock()
			if relay != nil {
				_ = relay.Send([]byte{0x00})
			}
		}
	}
}

func (t *YandexVolgaTransport) recoverSession(refreshAuth bool) error {
	t.recoverMu.Lock()
	defer t.recoverMu.Unlock()
	if !t.IsRunning() {
		return context.Canceled
	}

	t.relayMu.RLock()
	auth := t.auth
	t.relayMu.RUnlock()
	if refreshAuth {
		var err error
		auth, err = authorize(t.docURL)
		if err != nil {
			return err
		}
	}
	if auth == nil {
		return fmt.Errorf("transport has no authorization")
	}

	newRelay := newRelayClient(auth, t.config, t.stats)
	newRelay.Start()
	if !refreshAuth {
		t.relayMu.Lock()
		oldRelay, ws := t.relay, t.ws
		t.relay = newRelay
		if ws != nil {
			ws.SetRelay(newRelay)
		}
		t.relayMu.Unlock()
		if oldRelay != nil {
			oldRelay.Stop()
		}
		utils.Debugf("[VOLGA] relay pool rebuilt: user=%d rp=%s", auth.UserID, auth.RequestPath)
		return nil
	}

	newWS := newWSListener(auth, t.config, t.stats, newRelay, func(data []byte) {
		t.onDataMu.RLock()
		cb := t.onData
		t.onDataMu.RUnlock()
		if cb != nil {
			cb(data)
		}
		t.RecordReceive(len(data))
	})
	newWS.Start()

	t.relayMu.Lock()
	oldWS, oldRelay := t.ws, t.relay
	t.auth, t.relay, t.ws = auth, newRelay, newWS
	t.tokenExpiry = auth.TokenTTL
	t.relayMu.Unlock()
	if oldWS != nil {
		oldWS.Stop()
	}
	if oldRelay != nil {
		oldRelay.Stop()
	}
	t.SetConnected(true)
	utils.Debugf("[VOLGA] session rebuilt: user=%d rp=%s", auth.UserID, auth.RequestPath)
	return nil
}

func (t *YandexVolgaTransport) statsLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var lastSent, lastBytes, lastHTTP, lastFailed, lastRecv, lastRecvBytes, lastBatches, lastBatched uint64

	for {
		select {
		case <-t.keepAliveStop:
			return
		case <-ticker.C:
			sent := t.stats.PacketsSent.Load()
			bytes := t.stats.BytesSent.Load()
			httpReqs := t.stats.HTTPReqsSent.Load()
			failed := t.stats.HTTPReqsFailed.Load()
			recv := t.stats.PacketsRecv.Load()
			recvBytes := t.stats.BytesReceived.Load()
			batches := t.stats.BatchesSent.Load()
			batched := t.stats.PacketsBatched.Load()

			utils.Debugf("[VOLGA-STATS] send %d pkt/s (%d KB/s) | http %d req/s fail %d | batch %d (avg %.1f pkt) | recv %d pkt/s (%d KB/s) | busy %d/%d | order %d dup %d gaps %d",
				(sent-lastSent)/5, (bytes-lastBytes)/5/1024,
				(httpReqs-lastHTTP)/5, failed-lastFailed,
				(batches-lastBatches)/5,
				float64(batched-lastBatched)/float64(maxU64(batches-lastBatches, 1)),
				(recv-lastRecv)/5, (recvBytes-lastRecvBytes)/5/1024,
				t.stats.WorkerBusy.Load(), t.config.WorkerCount,
				t.stats.OutOfOrder.Load(), t.stats.Duplicates.Load(), t.stats.GapsSkipped.Load())

			lastSent, lastBytes = sent, bytes
			lastHTTP, lastFailed = httpReqs, failed
			lastRecv, lastRecvBytes = recv, recvBytes
			lastBatches, lastBatched = batches, batched
		}
	}
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
