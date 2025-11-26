package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
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
)

const (
	defaultSourcesFile  = "./config/sub.txt"
	defaultBadWordsFile = "./config/bad.txt"
	defaultUAgentFile   = "./config/uagent.txt"
	defaultCacheDir     = "./cache"
)

type SourceMap map[string]string

var (
	cacheDir  string
	cacheTTL  time.Duration
	sources   SourceMap
	badWords  []string
	allowedUA []string
	mu        sync.RWMutex
)

var builtinAllowedPrefixes = []string{"clash", "happ"}

// LineProcessor defines how to transform a line
type LineProcessor func(string) string

// loadTextFile reads a text file, skips empty lines and comments, applies processor
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

	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot create cache dir: %v\n", err)
		os.Exit(1)
	}

	// Load sources: special case (map with auto-numbered keys)
	{
		lines, err := loadTextFile(sourcesFile, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load sources: %v\n", err)
			os.Exit(1)
		}
		sources = make(SourceMap)
		for i, line := range lines {
			sources[strconv.Itoa(i+1)] = line
		}
	}

	// Load bad words: to lower case
	var err error
	badWords, err = loadTextFile(badWordsFile, strings.ToLower)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load bad words: %v (using empty list)\n", err)
		badWords = []string{}
	}

	// Load user agents: as-is
	allowedUA, err = loadTextFile(uagentFile, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Note: using built-in User-Agent rules only (no %s or error: %v)\n", uagentFile, err)
		allowedUA = []string{}
	}

	http.HandleFunc("/filter", handler)
	fmt.Printf("Server starting on :%s\n", port)
	fmt.Printf("Sources: %s\n", sourcesFile)
	fmt.Printf("Bad words: %s\n", badWordsFile)
	fmt.Printf("User-Agent file: %s\n", uagentFile)
	fmt.Printf("Cache TTL: %ds\n", cacheTTLSeconds)
	if len(allowedUA) > 0 {
		fmt.Printf("Additional allowed User-Agents loaded: %d entries\n", len(allowedUA))
	} else {
		fmt.Println("Using built-in User-Agent rules: 'clash' or 'happ' (case-insensitive)")
	}
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Server failed: %v\n", err)
		os.Exit(1)
	}
}

// isValidUserAgent checks if UA is allowed
func isValidUserAgent(ua string) bool {
	lowerUA := strings.ToLower(ua)

	// 1. Built-in prefixes
	for _, prefix := range builtinAllowedPrefixes {
		if strings.HasPrefix(lowerUA, prefix) {
			return true
		}
	}

	// 2. Custom list from uagent.txt (substring match, case-insensitive)
	mu.RLock()
	defer mu.RUnlock()
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
	userAgent := r.Header.Get("User-Agent")
	if !isValidUserAgent(userAgent) {
		http.Error(w, "Forbidden: invalid User-Agent", http.StatusForbidden)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing id", http.StatusBadRequest)
		return
	}

	mu.RLock()
	sourceURL, exists := sources[id]
	mu.RUnlock()
	if !exists {
		http.Error(w, "Invalid id", http.StatusBadRequest)
		return
	}

	origCache := filepath.Join(cacheDir, "orig_"+id+".txt")
	modCache := filepath.Join(cacheDir, "mod_"+id+".txt")

	// Try mod cache first
	if info, err := os.Stat(modCache); err == nil {
		if time.Since(info.ModTime()) <= cacheTTL {
			content, err := os.ReadFile(modCache)
			if err == nil {
				serveFile(w, r, content, sourceURL, id)
				return
			}
		}
	}

	// Fetch original
	var origContent []byte
	if info, err := os.Stat(origCache); err == nil && time.Since(info.ModTime()) <= cacheTTL {
		origContent, err = os.ReadFile(origCache)
		if err != nil {
			http.Error(w, "Failed to read origin cache", http.StatusInternalServerError)
			return
		}
	} else {
		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
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

		origContent, err = io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to read response: %v", err), http.StatusBadGateway)
			return
		}

		_ = os.WriteFile(origCache, origContent, 0644)
	}

	// Process lines
	lines := bytes.Split(origContent, []byte("\n"))
	var out []string

	for _, lineBytes := range lines {
		line := strings.TrimRight(string(lineBytes), "\r\n")
		if line == "" {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(line), "vless://") {
			continue
		}

		u, err := url.Parse(line)
		if err != nil || u.Scheme != "vless" {
			continue
		}

		uuid := u.User.Username()
		host := u.Hostname()
		portStr := u.Port()
		var port int
		if portStr != "" {
			port, err = strconv.Atoi(portStr)
			if err != nil || port <= 0 || port > 65535 {
				continue
			}
		}

		if !isValidUUID(uuid) || !isValidHost(host) || (portStr != "" && !isValidPort(port)) {
			continue
		}

		fragmentEncoded := u.Fragment
		fragmentDecoded := fragmentEncoded
		if fragmentEncoded != "" {
			if decoded, err := url.QueryUnescape(fragmentEncoded); err == nil {
				fragmentDecoded = decoded
			}
		}

		if isForbiddenAnchor(fragmentEncoded) {
			continue
		}

		query := u.RawQuery
		newQuery := normalizeALPN(query)
		if isOnlyEncryptionSecurityTypeGRPC(newQuery) {
			continue
		}

		// Rebuild URI
		var buf strings.Builder
		buf.WriteString("vless://")
		buf.WriteString(url.PathEscape(uuid))
		buf.WriteString("@")
		if net.ParseIP(host) != nil && strings.Contains(host, ":") {
			buf.WriteString("[" + host + "]")
		} else {
			buf.WriteString(host)
		}
		if portStr != "" {
			buf.WriteString(":")
			buf.WriteString(portStr)
		}
		if u.Path != "" {
			buf.WriteString(u.Path)
		}
		if newQuery != "" {
			buf.WriteString("?")
			buf.WriteString(newQuery)
		}
		if fragmentDecoded != "" {
			buf.WriteString("#")
			buf.WriteString(fragmentDecoded)
		}

		out = append(out, buf.String())
	}

	// --- ДОБАВЛЕНИЕ ЗАГОЛОВКА ПРОФИЛЯ ---
	sourceHost := "unknown"
	if parsedSource, err := url.Parse(sourceURL); err == nil && parsedSource.Host != "" {
		// Разделяем хост и порт (если порт есть)
		if host, _, err := net.SplitHostPort(parsedSource.Host); err == nil {
			sourceHost = host
		} else {
			// Порт отсутствует — весь Host и есть имя хоста
			sourceHost = parsedSource.Host
		}
	}

	// Округление TTL вверх до ближайшего часа
	ttlHours := int64((cacheTTL + time.Hour - 1) / time.Hour)
	if ttlHours < 1 {
		ttlHours = 1
	}

	profileTitle := fmt.Sprintf("#profile-title: %s filtered %s", sourceHost, id)
	profileInterval := fmt.Sprintf("#profile-update-interval: %d", ttlHours)

	// Формируем финальный файл: заголовок + пустая строка + URI
	finalLines := []string{profileTitle, profileInterval, ""}
	finalLines = append(finalLines, out...)
	final := strings.Join(finalLines, "\n")

	_ = os.WriteFile(modCache, []byte(final), 0644)
	serveFile(w, r, []byte(final), sourceURL, id)
}

func serveFile(w http.ResponseWriter, r *http.Request, content []byte, sourceURL, id string) {
	u, err := url.Parse(sourceURL)
	filename := "filtered_" + id + ".txt"
	if err == nil {
		base := path.Base(u.Path)
		if base != "" && regexp.MustCompile(`^[a-zA-Z0-9._-]+\.txt$`).MatchString(base) {
			filename = base
		}
	}
	filename = regexp.MustCompile(`[^a-zA-Z0-9._-]`).ReplaceAllString(filename, "_")
	if !strings.HasSuffix(strings.ToLower(filename), ".txt") {
		filename += ".txt"
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.Write(content)
}

// --- Validation helpers ---

var (
	uuidRegex1 = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	uuidRegex2 = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	hostRegex  = regexp.MustCompile(`^([a-z0-9_][a-z0-9_-]*\.)*[a-z0-9_][a-z0-9_-]*$`)
)

func isValidUUID(uuid string) bool {
	return uuid != "" && (uuidRegex1.MatchString(uuid) || uuidRegex2.MatchString(uuid))
}

func isValidHost(host string) bool {
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil {
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

	values, err := url.ParseQuery(query)
	if err != nil {
		return query
	}

	alpnValues := values["alpn"]
	var pairs []string

	for key, vals := range values {
		if strings.ToLower(key) == "alpn" {
			continue
		}
		for _, v := range vals {
			pairs = append(pairs, url.QueryEscape(key)+"="+url.QueryEscape(v))
		}
	}

	if len(alpnValues) > 0 {
		pairs = append(pairs, "alpn="+url.QueryEscape(alpnValues[0]))
	}

	return strings.Join(pairs, "&")
}

func isOnlyEncryptionSecurityTypeGRPC(query string) bool {
	if query == "" {
		return false
	}

	values, err := url.ParseQuery(query)
	if err != nil {
		return false
	}

	if len(values) != 3 {
		return false
	}

	enc := strings.ToLower(values.Get("encryption"))
	sec := strings.ToLower(values.Get("security"))
	typ := strings.ToLower(values.Get("type"))

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

	mu.RLock()
	defer mu.RUnlock()
	for _, word := range badWords {
		if strings.Contains(decodedLower, word) {
			return true
		}
	}
	return false
}
