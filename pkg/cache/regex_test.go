package cache

// pkg/cache/regex_test.go

import (
	"testing"
)

func TestRegexCache_Get(t *testing.T) {
	cache := NewRegexCache()

	// Тест компиляции валидного паттерна
	pattern := `^[a-zA-Z0-9_]+$`
	re1, err := cache.Get(pattern)
	if err != nil {
		t.Fatalf("Failed to compile valid pattern: %v", err)
	}
	if re1 == nil {
		t.Fatal("Regex is nil")
	}

	// Получаем тот же паттерн еще раз - должен вернуться кэшированный
	re2, err := cache.Get(pattern)
	if err != nil {
		t.Fatalf("Failed to get cached pattern: %v", err)
	}
	if re1 != re2 {
		t.Error("Expected same regex instance from cache")
	}

	// Проверяем размер кэша
	if cache.Size() != 1 {
		t.Errorf("Expected cache size 1, got %d", cache.Size())
	}
}

func TestRegexCache_InvalidPattern(t *testing.T) {
	cache := NewRegexCache()

	// Тест невалидного паттерна
	invalidPattern := `[a-z`
	_, err := cache.Get(invalidPattern)
	if err == nil {
		t.Error("Expected error for invalid regex pattern")
	}

	// Кэш не должен содержать невалидный паттерн
	if cache.Size() != 0 {
		t.Errorf("Expected cache size 0 for invalid pattern, got %d", cache.Size())
	}
}

func TestRegexCache_Statistics(t *testing.T) {
	cache := NewRegexCache()

	pattern := `^[a-zA-Z0-9_]+$`

	// Первый вызов - miss
	re1, err := cache.Get(pattern)
	if err != nil {
		t.Fatalf("Failed to compile pattern: %v", err)
	}

	// Второй вызов - hit
	re2, err := cache.Get(pattern)
	if err != nil {
		t.Fatalf("Failed to get cached pattern: %v", err)
	}

	if re1 != re2 {
		t.Error("Expected same regex instance")
	}

	hits, misses := cache.Statistics()
	if misses != 1 {
		t.Errorf("Expected 1 miss, got %d", misses)
	}
	if hits != 1 {
		t.Errorf("Expected 1 hit, got %d", hits)
	}
}

func TestRegexCache_Clear(t *testing.T) {
	cache := NewRegexCache()

	// Добавляем паттерн
	pattern := `test`
	_, err := cache.Get(pattern)
	if err != nil {
		t.Fatalf("Failed to compile pattern: %v", err)
	}

	if cache.Size() != 1 {
		t.Errorf("Expected cache size 1, got %d", cache.Size())
	}

	// Очищаем кэш
	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("Expected cache size 0 after clear, got %d", cache.Size())
	}
}

func BenchmarkRegexCache_Get(b *testing.B) {
	cache := NewRegexCache()
	pattern := `^[a-zA-Z0-9_]{1,64}$`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cache.Get(pattern)
		if err != nil {
			b.Fatalf("Failed to get regex: %v", err)
		}
	}
}

func BenchmarkRegexCache_GetParallel(b *testing.B) {
	cache := NewRegexCache()
	pattern := `^[a-zA-Z0-9_]{1,64}$`

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := cache.Get(pattern)
			if err != nil {
				b.Fatalf("Failed to get regex: %v", err)
			}
		}
	})
}
