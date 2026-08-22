// pkg/service/bench_format_test.go
package service

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sub-filter/internal/validator"
	"sub-filter/pkg/config"
	"sub-filter/pkg/logger"
)

// benchService собирает сервис с реальными процессорами протоколов.
func benchService(b *testing.B) *Service {
	b.Helper()
	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Cache:  config.CacheConfig{Directory: os.TempDir(), TTL: 30 * time.Minute},
	}
	log := logger.NewDefault(logger.ParseLevel("error"))
	opts := &ServiceOptions{
		Sources: make(map[string]*config.SafeSource),
		Rules:   make(map[string]validator.Validator),
	}
	svc, err := NewService(cfg, log, opts)
	if err != nil {
		b.Fatalf("failed to create service: %v", err)
	}
	return svc
}

// benchLines загружает строки-ссылки из файла-примера.
func benchLines(b *testing.B) []string {
	b.Helper()
	data, err := os.ReadFile(filepath.Clean("../../tmp/test.txt"))
	if err != nil {
		b.Skipf("sample file not found: %v", err)
	}
	var lines []string
	for _, l := range splitLines(string(data)) {
		if l == "" || l[0] == '#' {
			continue
		}
		lines = append(lines, l)
	}
	return lines
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// BenchmarkProcessLine — горячий путь: парсинг+валидация+нормализация одной ссылки.
func BenchmarkProcessLine(b *testing.B) {
	svc := benchService(b)
	lines := benchLines(b)
	procs := svc.createProxyProcessors()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		line := lines[i%len(lines)]
		for _, p := range procs {
			if p.Matches(line) {
				p.Process(line)
				break
			}
		}
	}
}

// BenchmarkProcessAllLines — полный проход по всем ссылкам файла.
func BenchmarkProcessAllLines(b *testing.B) {
	svc := benchService(b)
	lines := benchLines(b)
	procs := svc.createProxyProcessors()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, line := range lines {
			for _, p := range procs {
				if p.Matches(line) {
					p.Process(line)
					break
				}
			}
		}
	}
}

// BenchmarkContentToYAML — преобразование всего файла в YAML.
func BenchmarkContentToYAML(b *testing.B) {
	data, err := os.ReadFile(filepath.Clean("../../tmp/test.txt"))
	if err != nil {
		b.Skipf("sample file not found: %v", err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		contentToYAML(data)
	}
}

// BenchmarkBase64Encode — кодирование результата в base64.
func BenchmarkBase64Encode(b *testing.B) {
	data, err := os.ReadFile(filepath.Clean("../../tmp/test.txt"))
	if err != nil {
		b.Skipf("sample file not found: %v", err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		base64.StdEncoding.EncodeToString(data)
	}
}

// BenchmarkFormatYAML — полный формат yaml (конверсия + content-type).
func BenchmarkFormatYAML(b *testing.B) {
	data, err := os.ReadFile(filepath.Clean("../../tmp/test.txt"))
	if err != nil {
		b.Skipf("sample file not found: %v", err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		formatContent(data, "yaml")
	}
}

// BenchmarkBadWordFilter — фильтрация bad-word по фрагментам.
func BenchmarkBadWordFilter(b *testing.B) {
	svc := benchService(b)
	lines := benchLines(b)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		line := lines[i%len(lines)]
		svc.applyReplaceBadWords(line)
	}
}
