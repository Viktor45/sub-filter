// Пакет main реализует утилиту для фильтрации прокси-подписок.
// Поддерживает два режима работы:
//   - HTTP-сервер для динамической фильтрации (/filter?id=1)
//   - CLI-режим для однократной обработки всех подписок (--cli)
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "time/tzdata"

	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"

	"sub-filter/hysteria2"
	"sub-filter/internal/utils"
	"sub-filter/ss"
	"sub-filter/trojan"
	"sub-filter/vless"
	"sub-filter/vmess"
)

const (
	maxIDLength     = 64
	maxURILength    = 4096
	maxSourceBytes  = 10 * 1024 * 1024
	limiterBurst    = 5
	limiterEvery    = 100 * time.Millisecond
	cleanupInterval = 2 * time.Minute
	inactiveTimeout = 30 * time.Minute
)

var defaultCacheDir = filepath.Join(os.TempDir(), "sub-filter-cache")

type SafeSource struct {
	URL string
	IP  net.IP
}

type SourceMap map[string]*SafeSource

type AppConfig struct {
	CacheDir     string
	CacheTTL     time.Duration
	SourcesFile  string
	BadWordsFile string
	UAgentFile   string
	AllowedUA    []string
	BadWords     []string
	Sources      SourceMap
}

func (cfg *AppConfig) Init() {
	if cfg.CacheDir == "" {
		cfg.CacheDir = defaultCacheDir
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 30 * time.Minute
	}
	if cfg.SourcesFile == "" {
		cfg.SourcesFile = "./config/sub.txt"
	}
	if cfg.BadWordsFile == "" {
		cfg.BadWordsFile = "./config/bad.txt"
	}
	if cfg.UAgentFile == "" {
		cfg.UAgentFile = "./config/uagent.txt"
	}
}

var (
	ipLimiter              = make(map[string]*rate.Limiter)
	ipLastSeen             = make(map[string]time.Time)
	limiterMutex           sync.RWMutex
	fetchGroup             singleflight.Group
	builtinAllowedPrefixes = []string{"clash", "happ"}
	validIDRe              = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
)

type ProxyLink interface {
	Matches(s string) bool
	Process(s string) (string, string)
}

func createProxyProcessors(badWords []string) []ProxyLink {
	checkBadWords := func(fragment string) (bool, string) {
		if fragment == "" {
			return false, ""
		}
		decoded := utils.FullyDecode(fragment)
		lower := strings.ToLower(decoded)
		for _, word := range badWords {
			if word != "" && strings.Contains(lower, word) {
				return true, fmt.Sprintf("bad word in name: %q", word)
			}
		}
		return false, ""
	}

	return []ProxyLink{
		vless.NewVLESSLink(badWords, utils.IsValidHost, utils.IsValidPort, checkBadWords),
		vmess.NewVMessLink(badWords, utils.IsValidHost, checkBadWords),
		trojan.NewTrojanLink(badWords, utils.IsValidHost, checkBadWords),
		ss.NewSSLink(badWords, utils.IsValidHost, checkBadWords),
		hysteria2.NewHysteria2Link(badWords, utils.IsValidHost, checkBadWords),
	}
}

func loadTextFile(filename string, processor func(string) string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	if b, err := reader.Peek(3); err == nil && bytes.Equal(b, []byte{0xEF, 0xBB, 0xBF}) {
		reader.Discard(3)
	}
	var result []string
	scanner := bufio.NewScanner(reader)
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

func getDefaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

func isIPAllowed(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast())
}

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
	if strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return isIPAllowed(ip)
	}
	return true
}

func getLimiter(ip string) *rate.Limiter {
	limiterMutex.Lock()
	defer limiterMutex.Unlock()
	ipLastSeen[ip] = time.Now()
	if limiter, exists := ipLimiter[ip]; exists {
		return limiter
	}
	limiter := rate.NewLimiter(rate.Every(limiterEvery), limiterBurst)
	ipLimiter[ip] = limiter
	return limiter
}

func cleanupLimiters(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			limiterMutex.RLock()
			var toDelete []string
			now := time.Now()
			for ip, last := range ipLastSeen {
				if now.Sub(last) > inactiveTimeout {
					toDelete = append(toDelete, ip)
				}
			}
			limiterMutex.RUnlock()
			if len(toDelete) > 0 {
				limiterMutex.Lock()
				for _, ip := range toDelete {
					delete(ipLimiter, ip)
					delete(ipLastSeen, ip)
				}
				limiterMutex.Unlock()
			}
		}
	}
}

func isValidUserAgent(ua string, allowedUA []string) bool {
	lowerUA := strings.ToLower(ua)
	for _, prefix := range builtinAllowedPrefixes {
		if strings.HasPrefix(lowerUA, prefix) {
			return true
		}
	}
	for _, allowed := range allowedUA {
		if allowed != "" && strings.Contains(lowerUA, strings.ToLower(allowed)) {
			return true
		}
	}
	return false
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
	filename = filepath.Base(filename)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.Write(content)
}

func isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

func processSource(id string, source *SafeSource, cfg *AppConfig, proxyProcessors []ProxyLink, stdout bool) (string, error) {
	parsedSource, err := url.Parse(source.URL)
	if err != nil || parsedSource.Host == "" {
		return "", fmt.Errorf("invalid source URL")
	}
	host := parsedSource.Hostname()
	if !utils.IsValidHost(host) {
		return "", fmt.Errorf("invalid source host: %s", host)
	}

	origCache := filepath.Join(cfg.CacheDir, "orig_"+id+".txt")
	modCache := filepath.Join(cfg.CacheDir, "mod_"+id+".txt")
	rejectedCache := filepath.Join(cfg.CacheDir, "rejected_"+id+".txt")

	if !utils.IsPathSafe(origCache, cfg.CacheDir) ||
		!utils.IsPathSafe(modCache, cfg.CacheDir) ||
		!utils.IsPathSafe(rejectedCache, cfg.CacheDir) {
		return "", fmt.Errorf("unsafe cache path for id=%s", id)
	}

	if !stdout {
		if info, err := os.Stat(modCache); err == nil && time.Since(info.ModTime()) <= cfg.CacheTTL {
			content, _ := os.ReadFile(modCache)
			return string(content), nil
		}
	}

	var origContent []byte
	if !stdout {
		if info, err := os.Stat(origCache); err == nil && time.Since(info.ModTime()) <= cfg.CacheTTL {
			if content, err := os.ReadFile(origCache); err == nil {
				origContent = content
			}
		}
	}

	if origContent == nil {
		_, portStr, _ := net.SplitHostPort(parsedSource.Host)
		if portStr == "" {
			portStr = getDefaultPort(parsedSource.Scheme)
		}
		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					dialer := &net.Dialer{Timeout: 5 * time.Second}
					return dialer.DialContext(ctx, network, net.JoinHostPort(source.IP.String(), portStr))
				},
				TLSClientConfig: &tls.Config{ServerName: host},
				MaxIdleConns:    10,
				IdleConnTimeout: 30 * time.Second,
			},
		}

		result, err, _ := fetchGroup.Do(id, func() (interface{}, error) {
			req, err := http.NewRequest("GET", source.URL, nil)
			if err != nil {
				return nil, fmt.Errorf("create request: %w", err)
			}
			req.Header.Set("User-Agent", "go-filter/1.0")
			resp, err := client.Do(req)
			if err != nil {
				return nil, fmt.Errorf("fetch failed: %w", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode >= 400 {
				return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
			}
			content, err := io.ReadAll(io.LimitReader(resp.Body, maxSourceBytes))
			if err != nil {
				return nil, fmt.Errorf("read failed: %w", err)
			}
			if !stdout {
				tmpFile := origCache + ".tmp"
				if err := os.WriteFile(tmpFile, content, 0o644); err == nil {
					_ = os.Rename(tmpFile, origCache)
				}
			}
			return content, nil
		})
		if err != nil {
			return "", err
		}
		origContent = result.([]byte)
	}

	hasProxy := bytes.Contains(origContent, []byte("vless://")) ||
		bytes.Contains(origContent, []byte("vmess://")) ||
		bytes.Contains(origContent, []byte("trojan://")) ||
		bytes.Contains(origContent, []byte("ss://")) ||
		bytes.Contains(origContent, []byte("hysteria2://")) ||
		bytes.Contains(origContent, []byte("hy2://"))

	if !hasProxy {
		decoded := utils.AutoDecodeBase64(origContent)
		if bytes.Contains(decoded, []byte("vless://")) ||
			bytes.Contains(decoded, []byte("vmess://")) ||
			bytes.Contains(decoded, []byte("trojan://")) ||
			bytes.Contains(decoded, []byte("ss://")) ||
			bytes.Contains(decoded, []byte("hysteria2://")) ||
			bytes.Contains(decoded, []byte("hy2://")) {
			origContent = decoded
		}
	}

	var out []string
	var rejectedLines []string
	lines := bytes.Split(origContent, []byte("\n"))
	for _, lineBytes := range lines {
		originalLine := strings.TrimRight(string(lineBytes), "\r\n")
		if originalLine == "" || strings.HasPrefix(originalLine, "#") {
			continue
		}
		var processedLine, reason string
		handled := false
		for _, p := range proxyProcessors {
			if p.Matches(originalLine) {
				processedLine, reason = p.Process(originalLine)
				handled = true
				break
			}
		}
		if !handled {
			reason = "unsupported protocol"
		}
		if processedLine != "" {
			out = append(out, processedLine)
		} else {
			if reason == "" {
				reason = "processing failed"
			}
			rejectedLines = append(rejectedLines, "# REASON: "+reason, originalLine)
		}
	}

	if !stdout && len(rejectedLines) > 0 {
		rejectedContent := strings.Join(rejectedLines, "\n")
		tmpFile := rejectedCache + ".tmp"
		if err := os.WriteFile(tmpFile, []byte(rejectedContent), 0o644); err == nil {
			_ = os.Rename(tmpFile, rejectedCache)
		}
	} else if !stdout {
		_ = os.Remove(rejectedCache)
	}

	profileName := "filtered_" + id
	if u, err := url.Parse(source.URL); err == nil {
		base := path.Base(u.Path)
		if base != "" && regexp.MustCompile(`^[a-zA-Z0-9._-]+\.txt$`).MatchString(base) {
			profileName = strings.TrimSuffix(base, ".txt")
		}
	}
	profileName = regexp.MustCompile(`[^a-zA-Z0-9._-]`).ReplaceAllString(profileName, "_")
	updateInterval := int(cfg.CacheTTL.Seconds() / 3600)
	if updateInterval < 1 {
		updateInterval = 1
	}
	profileTitle := fmt.Sprintf("#profile-title: %s filtered %s", profileName, id)
	profileInterval := fmt.Sprintf("#profile-update-interval: %d", updateInterval)
	finalLines := []string{profileTitle, profileInterval, ""}
	finalLines = append(finalLines, out...)
	final := strings.Join(finalLines, "\n")

	if !stdout {
		tmpFile := modCache + ".tmp"
		if err := os.WriteFile(tmpFile, []byte(final), 0o644); err != nil {
			_ = os.Remove(tmpFile)
			return "", err
		}
		_ = os.Rename(tmpFile, modCache)
	}

	return final, nil
}

func loadSourcesFromFile(sourcesFile string) (SourceMap, error) {
	lines, err := loadTextFile(sourcesFile, nil)
	if err != nil {
		return nil, err
	}
	sources := make(SourceMap)
	validIndex := 1
	for _, line := range lines {
		if !isValidSourceURL(line) {
			fmt.Fprintf(os.Stderr, "Skipping invalid source: %s\n", line)
			continue
		}
		u, _ := url.Parse(line)
		host := u.Hostname()
		portStr := u.Port()
		if portStr == "" {
			portStr = getDefaultPort(u.Scheme)
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if isIPAllowed(ip) {
				sources[strconv.Itoa(validIndex)] = &SafeSource{URL: line, IP: ip}
				validIndex++
				break
			}
		}
	}
	return sources, nil
}

func loadConfigFromFile(configPath string) (*AppConfig, error) {
	viper.SetConfigFile(configPath)
	ext := filepath.Ext(configPath)
	if ext == ".yaml" || ext == ".yml" {
		viper.SetConfigType("yaml")
	}
	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}
	var cfg AppConfig
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	cfg.Init()
	if len(cfg.Sources) == 0 {
		sources, err := loadSourcesFromFile(cfg.SourcesFile)
		if err != nil {
			return nil, err
		}
		cfg.Sources = sources
	}
	if len(cfg.BadWords) == 0 {
		bw, _ := loadTextFile(cfg.BadWordsFile, strings.ToLower)
		cfg.BadWords = bw
	}
	if len(cfg.AllowedUA) == 0 {
		ua, _ := loadTextFile(cfg.UAgentFile, nil)
		cfg.AllowedUA = ua
	}
	return &cfg, nil
}

func main() {
	var (
		cliMode = flag.Bool("cli", false, "Run in CLI mode")
		stdout  = flag.Bool("stdout", false, "Print results to stdout (CLI only)")
		config  = flag.String("config", "", "Path to config file (YAML/JSON/TOML)")
	)
	flag.Parse()

	if *cliMode {
		var cfg *AppConfig
		var err error

		if *config != "" {
			cfg, err = loadConfigFromFile(*config)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
				os.Exit(1)
			}
		} else {
			cacheTTLSeconds := 1800
			sourcesFile := "./config/sub.txt"
			badWordsFile := "./config/bad.txt"
			uagentFile := "./config/uagent.txt"

			args := flag.Args()
			if len(args) >= 1 {
				if sec, e := strconv.Atoi(args[0]); e == nil && sec > 0 {
					cacheTTLSeconds = sec
				}
			}
			if len(args) >= 2 {
				sourcesFile = args[1]
			}
			if len(args) >= 3 {
				badWordsFile = args[2]
			}
			if len(args) >= 4 {
				uagentFile = args[3]
			}

			cfg = &AppConfig{
				CacheTTL:     time.Duration(cacheTTLSeconds) * time.Second,
				SourcesFile:  sourcesFile,
				BadWordsFile: badWordsFile,
				UAgentFile:   uagentFile,
			}
			cfg.Init()
			cfg.Sources, err = loadSourcesFromFile(cfg.SourcesFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Load sources: %v\n", err)
				os.Exit(1)
			}
			cfg.BadWords, _ = loadTextFile(cfg.BadWordsFile, strings.ToLower)
			cfg.AllowedUA, _ = loadTextFile(cfg.UAgentFile, nil)
		}

		if err := os.MkdirAll(cfg.CacheDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "Create cache dir: %v\n", err)
			os.Exit(1)
		}

		proxyProcessors := createProxyProcessors(cfg.BadWords)

		g, _ := errgroup.WithContext(context.Background())
		var mu sync.Mutex
		var outputs []string

		for id, source := range cfg.Sources {
			id, source := id, source
			g.Go(func() error {
				result, err := processSource(id, source, cfg, proxyProcessors, *stdout)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Process failed %s: %v\n", id, err)
					return nil
				}
				if *stdout {
					mu.Lock()
					outputs = append(outputs, fmt.Sprintf("# Source %s\n%s", id, result))
					mu.Unlock()
				} else {
					fmt.Printf("Success: mod_%s.txt saved\n", id)
				}
				return nil
			})
		}

		_ = g.Wait()

		if *stdout {
			for _, out := range outputs {
				fmt.Println(out)
			}
		}
		return
	}

	if len(flag.Args()) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s <port> [cache_ttl] [sources] [bad] [ua]\n", os.Args[0])
		os.Exit(1)
	}

	port := flag.Args()[0]
	cacheTTLSeconds := 1800
	sourcesFile := "./config/sub.txt"
	badWordsFile := "./config/bad.txt"
	uagentFile := "./config/uagent.txt"

	if len(flag.Args()) >= 2 {
		if sec, err := strconv.Atoi(flag.Args()[1]); err == nil && sec > 0 {
			cacheTTLSeconds = sec
		}
	}
	if len(flag.Args()) >= 3 {
		sourcesFile = flag.Args()[2]
	}
	if len(flag.Args()) >= 4 {
		badWordsFile = flag.Args()[3]
	}
	if len(flag.Args()) >= 5 {
		uagentFile = flag.Args()[4]
	}

	cfg := &AppConfig{
		CacheDir:     defaultCacheDir,
		CacheTTL:     time.Duration(cacheTTLSeconds) * time.Second,
		SourcesFile:  sourcesFile,
		BadWordsFile: badWordsFile,
		UAgentFile:   uagentFile,
	}
	cfg.Init()

	if err := os.MkdirAll(cfg.CacheDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Create cache dir: %v\n", err)
		os.Exit(1)
	}

	var err error
	cfg.Sources, err = loadSourcesFromFile(cfg.SourcesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Load sources: %v\n", err)
		os.Exit(1)
	}
	cfg.BadWords, _ = loadTextFile(cfg.BadWordsFile, strings.ToLower)
	cfg.AllowedUA, _ = loadTextFile(cfg.UAgentFile, nil)

	proxyProcessors := createProxyProcessors(cfg.BadWords)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go cleanupLimiters(ctx)

	http.HandleFunc("/filter", func(w http.ResponseWriter, r *http.Request) {
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}
		if !isLocalIP(clientIP) {
			limiter := getLimiter(clientIP)
			if !limiter.Allow() {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}
		if !isValidUserAgent(r.Header.Get("User-Agent"), cfg.AllowedUA) {
			http.Error(w, "Forbidden: invalid User-Agent", http.StatusForbidden)
			return
		}
		id := r.URL.Query().Get("id")
		if id == "" || len(id) > maxIDLength || !validIDRe.MatchString(id) {
			http.Error(w, "Invalid id", http.StatusBadRequest)
			return
		}
		source, exists := cfg.Sources[id]
		if !exists {
			http.Error(w, "Invalid id", http.StatusBadRequest)
			return
		}
		if _, err := processSource(id, source, cfg, proxyProcessors, false); err != nil {
			http.Error(w, fmt.Sprintf("Processing error: %v", err), http.StatusInternalServerError)
			return
		}
		content, err := os.ReadFile(filepath.Join(cfg.CacheDir, "mod_"+id+".txt"))
		if err != nil {
			http.Error(w, "Result not found", http.StatusNotFound)
			return
		}
		serveFile(w, r, content, source.URL, id)
	})

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Listen: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Proxy Filter Server Starting...\n")
	fmt.Printf("Port: %s\n", port)
	fmt.Printf("Cache TTL: %d sec\n", cacheTTLSeconds)
	fmt.Printf("Cache dir: %s\n", cfg.CacheDir)
	fmt.Printf("Sources: %d\n", len(cfg.Sources))

	server := &http.Server{
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	errChan := make(chan error, 1)
	go func() { errChan <- server.Serve(listener) }()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errChan:
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	case <-sigChan:
		fmt.Println("\nShutting down gracefully...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "Force shutdown: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Println("Server stopped.")
}
