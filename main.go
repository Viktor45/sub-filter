package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	defaultSourcesFile  = "./config/sub.txt"
	defaultBadWordsFile = "./config/bad.txt"
	defaultUAgentFile   = "./config/uagent.txt"
	defaultCacheDir     = "./cache"
	maxIDLength         = 64
	maxURILength        = 4096
	maxUserinfoLength   = 1024
	maxSourceBytes      = 10 * 1024 * 1024 // 10 MB
)

type SourceMap map[string]string

var (
	cacheDir   string
	cacheTTL   time.Duration
	sources    SourceMap
	badWords   []string
	allowedUA  []string
	validIDRe  = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	uuidRegex1 = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hostRegex  = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	ssCipherRe = regexp.MustCompile(`^[a-zA-Z0-9_+-]+$`)

	// Rate limiter: 10 requests per second per IP, burst 5
	ipLimiter    = make(map[string]*rate.Limiter)
	limiterMutex sync.RWMutex
)

var builtinAllowedPrefixes = []string{"clash", "happ"}

type LineProcessor func(string) string

func loadTextFile(filename string, processor LineProcessor) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var result []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if processor != nil {
			line = processor(line)
		}
		result = append(result, line)
	}
	return result, scanner.Err()
}

// isValidSourceURL validates the URL structure (not DNS resolution)
func isValidSourceURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	if host == "localhost" {
		return false
	}
	if strings.HasPrefix(host, "127.") {
		return false
	}
	if strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".internal") {
		return false
	}
	if strings.HasPrefix(host, "xn--") {
		// Block IDN homograph attacks
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsMulticast() {
			return false
		}
	}
	return true
}

// isIPAllowed checks if an IP is safe to connect to
func isIPAllowed(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	// Block IPv6 with zone ID (e.g., fe80::1%eth0)
	if ip.To4() == nil && strings.Contains(ip.String(), "%") {
		return false
	}
	return true
}

// safeDialContext prevents SSRF by validating resolved IPs
func safeDialContext(ctx context.Context, network, addr string, originalHost string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address format")
	}

	// Resolve host
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	// Find first public, allowed IP
	var allowedIP net.IP
	for _, ip := range ips {
		if isIPAllowed(ip) {
			allowedIP = ip
			break
		}
	}

	if allowedIP == nil {
		return nil, fmt.Errorf("no public/resolvable IP for host %s", host)
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(allowedIP.String(), port))
}

func getLimiter(ip string) *rate.Limiter {
	limiterMutex.RLock()
	limiter, exists := ipLimiter[ip]
	limiterMutex.RUnlock()
	if !exists {
		limiterMutex.Lock()
		// Double-check
		limiter, exists = ipLimiter[ip]
		if !exists {
			limiter = rate.NewLimiter(rate.Every(100*time.Millisecond), 5) // 10 req/s
			ipLimiter[ip] = limiter
		}
		limiterMutex.Unlock()
	}
	return limiter
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <port> [cache_ttl_seconds] [sources_file] [bad_words_file] [uagent_file]\n", os.Args[0])
		os.Exit(1)
	}

	port := os.Args[1]
	cacheTTLSeconds := 1800
	if len(os.Args) >= 3 {
		if sec, err := strconv.Atoi(os.Args[2]); err == nil && sec > 0 {
			cacheTTLSeconds = sec
		}
	}
	sourcesFile := defaultSourcesFile
	if len(os.Args) >= 4 {
		sourcesFile = os.Args[3]
	}
	badWordsFile := defaultBadWordsFile
	if len(os.Args) >= 5 {
		badWordsFile = os.Args[4]
	}
	uagentFile := defaultUAgentFile
	if len(os.Args) >= 6 {
		uagentFile = os.Args[5]
	}

	cacheTTL = time.Duration(cacheTTLSeconds) * time.Second
	cacheDir = defaultCacheDir

	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot create cache dir: %v\n", err)
		os.Exit(1)
	}

	// Load and validate sources
	lines, err := loadTextFile(sourcesFile, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load sources: %v\n", err)
		os.Exit(1)
	}
	sources = make(SourceMap)
	validIndex := 1
	for _, line := range lines {
		if !isValidSourceURL(line) {
			fmt.Fprintf(os.Stderr, "⚠️  Skipping invalid or unsafe source URL: %s\n", line)
			continue
		}
		sources[strconv.Itoa(validIndex)] = line
		validIndex++
	}
	if len(sources) == 0 {
		fmt.Fprintf(os.Stderr, "No valid sources loaded. Exiting.\n")
		os.Exit(1)
	}

	// Load bad words
	badWords, err = loadTextFile(badWordsFile, strings.ToLower)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load bad words: %v (using empty list)\n", err)
		badWords = []string{}
	}

	// Load user agents
	allowedUA, err = loadTextFile(uagentFile, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Note: using built-in User-Agent rules only (no %s or error: %v)\n", uagentFile, err)
		allowedUA = []string{}
	}

	http.HandleFunc("/filter", handler)
	fmt.Printf("Server starting on :%s\n", port)
	fmt.Printf("Valid sources loaded: %d\n", len(sources))
	fmt.Printf("Bad words: %s\n", badWordsFile)
	fmt.Printf("User-Agent file: %s\n", uagentFile)
	fmt.Printf("Cache TTL: %ds\n", cacheTTLSeconds)

	server := &http.Server{
		Addr:         ":" + port,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "Server failed: %v\n", err)
		os.Exit(1)
	}
}

func isValidUserAgent(ua string) bool {
	lowerUA := strings.ToLower(ua)
	for _, prefix := range builtinAllowedPrefixes {
		if strings.HasPrefix(lowerUA, prefix) {
			return true
		}
	}
	for _, allowed := range allowedUA {
		if allowed == "" {
			continue
		}
		if strings.Contains(lowerUA, strings.ToLower(allowed)) {
			return true
		}
	}
	return false
}

func handler(w http.ResponseWriter, r *http.Request) {
	// Rate limiting per IP
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}
	limiter := getLimiter(clientIP)
	if !limiter.Allow() {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	if !isValidUserAgent(r.Header.Get("User-Agent")) {
		http.Error(w, "Forbidden: invalid User-Agent", http.StatusForbidden)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" || len(id) > maxIDLength || !validIDRe.MatchString(id) {
		http.Error(w, "Invalid id", http.StatusBadRequest)
		return
	}

	sourceURL, exists := sources[id]
	if !exists {
		http.Error(w, "Invalid id", http.StatusBadRequest)
		return
	}

	// Re-validate sourceURL to ensure it's safe and extract host
	parsedSource, err := url.Parse(sourceURL)
	if err != nil || parsedSource.Host == "" {
		http.Error(w, "Invalid source URL", http.StatusBadRequest)
		return
	}
	host := parsedSource.Hostname()
	if !isValidHost(host) {
		http.Error(w, "Invalid source host", http.StatusBadRequest)
		return
	}

	// Create safe cache file paths
	origCache := filepath.Join(cacheDir, "orig_"+id+".txt")
	modCache := filepath.Join(cacheDir, "mod_"+id+".txt")

	// Ensure cache file paths are within cacheDir to prevent path traversal
	if !isPathSafe(origCache, cacheDir) || !isPathSafe(modCache, cacheDir) {
		http.Error(w, "Invalid id", http.StatusBadRequest)
		return
	}

	// Try mod cache
	if info, err := os.Stat(modCache); err == nil && time.Since(info.ModTime()) <= cacheTTL {
		if content, err := os.ReadFile(modCache); err == nil {
			serveFile(w, r, content, sourceURL, id)
			return
		}
	}

	var origContent []byte
	if info, err := os.Stat(origCache); err == nil && time.Since(info.ModTime()) <= cacheTTL {
		if content, err := os.ReadFile(origCache); err == nil {
			origContent = content
		}
	}

	if origContent == nil {
		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return safeDialContext(ctx, network, addr, host)
				},
				TLSClientConfig: &tls.Config{
					ServerName: host,
				},
				MaxIdleConns:    10,
				IdleConnTimeout: 30 * time.Second,
			},
		}

		req, err := http.NewRequest("GET", sourceURL, nil)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid source URL: %v", err), http.StatusBadGateway)
			return
		}
		req.Header.Set("User-Agent", "go-filter/1.0")

		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to fetch source %s (error: %v)", sourceURL, err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 400 {
			http.Error(w, fmt.Sprintf("Failed to fetch source %s (HTTP %d)", sourceURL, resp.StatusCode), http.StatusBadGateway)
			return
		}

		origContent, err = io.ReadAll(io.LimitReader(resp.Body, maxSourceBytes))
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to read response: %v", err), http.StatusBadGateway)
			return
		}

		// Write original content atomically
		tmpFile := origCache + ".tmp"
		if err := os.WriteFile(tmpFile, origContent, 0o644); err == nil {
			if err := os.Rename(tmpFile, origCache); err != nil {
				// Log error or handle it, original file might be left if rename fails
				fmt.Fprintf(os.Stderr, "Failed to rename temp cache file: %v\n", err)
			}
		}
	}

	var out []string
	lines := bytes.Split(origContent, []byte("\n"))
	for _, lineBytes := range lines {
		line := strings.TrimRight(string(lineBytes), "\r\n")
		if line == "" {
			continue
		}
		if len(line) > maxURILength {
			continue
		}
		lowerLine := strings.ToLower(line)
		var filtered string
		switch {
		case strings.HasPrefix(lowerLine, "vless://"):
			filtered = processVLESS(line)
		case strings.HasPrefix(lowerLine, "ss://"):
			filtered = processSS(line)
		case strings.HasPrefix(lowerLine, "trojan://"):
			filtered = processTrojan(line)
		default:
			continue
		}
		if filtered != "" {
			out = append(out, filtered)
		}
	}

	// Profile header
	sourceHost := "unknown"
	if parsedSource, err := url.Parse(sourceURL); err == nil && parsedSource.Host != "" {
		if host, _, err := net.SplitHostPort(parsedSource.Host); err == nil {
			sourceHost = host
		} else {
			sourceHost = parsedSource.Host
		}
	}

	updateInterval := int(cacheTTL.Seconds() / 3600)
	if updateInterval < 1 {
		updateInterval = 1
	}

	profileTitle := fmt.Sprintf("#profile-title: %s filtered %s", sourceHost, id)
	profileInterval := fmt.Sprintf("#profile-update-interval: %d", updateInterval)

	finalLines := []string{profileTitle, profileInterval, ""}
	finalLines = append(finalLines, out...)
	final := strings.Join(finalLines, "\n")

	// Write modified content atomically
	tmpFile := modCache + ".tmp"
	if err := os.WriteFile(tmpFile, []byte(final), 0o644); err == nil {
		if err := os.Rename(tmpFile, modCache); err != nil {
			// Log error or handle it, modified file might be left if rename fails
			fmt.Fprintf(os.Stderr, "Failed to rename temp modified cache file: %v\n", err)
		}
	}

	serveFile(w, r, []byte(final), sourceURL, id)
}

func serveFile(w http.ResponseWriter, r *http.Request, content []byte, sourceURL, id string) {
	filename := "filtered_" + id + ".txt"
	if u, err := url.Parse(sourceURL); err == nil {
		base := path.Base(u.Path)
		if base != "" && regexp.MustCompile(`^[a-zA-Z0-9._-]+\.txt$`).MatchString(base) {
			filename = base
		}
	}
	filename = regexp.MustCompile(`[^a-zA-Z0-9._-]`).ReplaceAllString(filename, "_")
	if !strings.HasSuffix(strings.ToLower(filename), ".txt") {
		filename += ".txt"
	}

	// Ensure filename is safe by taking only the base name
	filename = filepath.Base(filename)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.Write(content)
}

// isPathSafe checks if the path is within the allowed directory
func isPathSafe(p, baseDir string) bool {
	cleanPath := filepath.Clean(p)
	rel, err := filepath.Rel(baseDir, cleanPath)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."
}

// === VLESS ===
func processVLESS(raw string) string {
	if len(raw) > maxURILength {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "vless" {
		return ""
	}

	uuid := u.User.Username()
	host := u.Hostname()
	portStr := u.Port()

	if portStr == "" {
		return ""
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || !isValidPort(port) {
		return ""
	}

	if !isValidUUID(uuid) || !isValidHost(host) {
		return ""
	}

	if isForbiddenAnchor(u.Fragment) {
		return ""
	}

	query := normalizeALPN(u.RawQuery)
	if isOnlyEncryptionSecurityTypeGRPC(query) {
		return ""
	}

	var buf strings.Builder
	buf.WriteString("vless://")
	buf.WriteString(url.PathEscape(uuid))
	buf.WriteString("@")
	buf.WriteString(net.JoinHostPort(host, portStr))
	if u.Path != "" {
		buf.WriteString(u.Path)
	}
	if query != "" {
		buf.WriteString("?")
		buf.WriteString(query)
	}
	if u.Fragment != "" {
		buf.WriteString("#")
		buf.WriteString(u.Fragment)
	}
	return buf.String()
}

// === Shadowsocks ===
func processSS(raw string) string {
	if len(raw) > maxURILength {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "ss" {
		return ""
	}

	userinfo := u.User.String()
	if userinfo == "" || len(userinfo) > maxUserinfoLength {
		return ""
	}

	var decoded []byte
	var decodeErr error
	if strings.HasSuffix(userinfo, "=") {
		decoded, decodeErr = base64.URLEncoding.DecodeString(userinfo)
	} else {
		decoded, decodeErr = base64.RawURLEncoding.DecodeString(userinfo)
	}
	if decodeErr != nil {
		return ""
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return ""
	}
	cipher, password := parts[0], parts[1]
	if cipher == "" || password == "" {
		return ""
	}
	if !ssCipherRe.MatchString(cipher) {
		return ""
	}

	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		return ""
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || !isValidPort(port) {
		return ""
	}
	if !isValidHost(host) {
		return ""
	}

	if isForbiddenAnchor(u.Fragment) {
		return ""
	}

	newUser := base64.RawURLEncoding.EncodeToString([]byte(cipher + ":" + password))
	var buf strings.Builder
	buf.WriteString("ss://")
	buf.WriteString(newUser)
	buf.WriteString("@")
	buf.WriteString(net.JoinHostPort(host, portStr))
	if u.Fragment != "" {
		buf.WriteString("#")
		buf.WriteString(u.Fragment)
	}
	return buf.String()
}

// === Trojan ===
func processTrojan(raw string) string {
	if len(raw) > maxURILength {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "trojan" {
		return ""
	}

	password := u.User.Username()
	if password == "" {
		return ""
	}

	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		return ""
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || !isValidPort(port) {
		return ""
	}
	if !isValidHost(host) {
		return ""
	}

	if isForbiddenAnchor(u.Fragment) {
		return ""
	}

	var buf strings.Builder
	buf.WriteString("trojan://")
	buf.WriteString(url.PathEscape(password))
	buf.WriteString("@")
	buf.WriteString(net.JoinHostPort(host, portStr))
	if u.RawQuery != "" {
		buf.WriteString("?")
		buf.WriteString(u.RawQuery)
	}
	if u.Fragment != "" {
		buf.WriteString("#")
		buf.WriteString(u.Fragment)
	}
	return buf.String()
}

// === Helpers ===
func isValidUUID(uuid string) bool {
	return uuid != "" && uuidRegex1.MatchString(uuid)
}

func isValidHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.HasPrefix(host, "xn--") {
		return false // block IDN
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	return hostRegex.MatchString(strings.ToLower(host))
}

func isValidPort(port int) bool {
	return port > 0 && port <= 65535
}

func normalizeALPN(query string) string {
	if query == "" {
		return ""
	}
	vals, err := url.ParseQuery(query)
	if err != nil {
		return query
	}
	if alpnList := vals["alpn"]; len(alpnList) > 0 {
		vals["alpn"] = alpnList[:1]
	}
	return vals.Encode()
}

func isOnlyEncryptionSecurityTypeGRPC(query string) bool {
	if query == "" {
		return false
	}
	vals, err := url.ParseQuery(query)
	if err != nil {
		return false
	}
	if len(vals) != 3 {
		return false
	}
	enc := strings.ToLower(vals.Get("encryption"))
	sec := strings.ToLower(vals.Get("security"))
	typ := strings.ToLower(vals.Get("type"))
	return enc == "none" && sec == "none" && typ == "grpc"
}

func isForbiddenAnchor(fragment string) bool {
	if fragment == "" {
		return false
	}
	decoded, err := url.QueryUnescape(fragment)
	if err != nil {
		decoded = fragment
	}
	decodedLower := strings.ToLower(decoded)
	for _, word := range badWords {
		if word != "" && strings.Contains(decodedLower, word) {
			return true
		}
	}
	return false
}
