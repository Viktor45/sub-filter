package cache

import (
	"regexp"
	"sync"
)

// RegexCache представляет кэш скомпилированных регулярных выражений
type RegexCache struct {
	cache sync.Map
	stats RegexCacheStats
}

// RegexCacheStats содержит статистику кэша
type RegexCacheStats struct {
	Hits   uint64
	Misses uint64
	mu     sync.RWMutex
}

// NewRegexCache создает новый кэш регулярных выражений
func NewRegexCache() *RegexCache {
	return &RegexCache{}
}

// Get возвращает скомпилированное регулярное выражение из кэша или компилирует новое
func (rc *RegexCache) Get(pattern string) (*regexp.Regexp, error) {
	// Try to get from cache
	if cached, ok := rc.cache.Load(pattern); ok {
		rc.recordHit()
		return cached.(*regexp.Regexp), nil
	}

	// Compile new regex
	re, err := regexp.Compile(pattern)
	if err != nil {
		rc.recordMiss()
		return nil, err
	}

	// Store in cache
	rc.cache.Store(pattern, re)
	rc.recordMiss()

	return re, nil
}

// Statistics возвращает статистику hits/misses
func (rc *RegexCache) Statistics() (hits, misses uint64) {
	rc.stats.mu.RLock()
	defer rc.stats.mu.RUnlock()
	return rc.stats.Hits, rc.stats.Misses
}

// Clear очищает кэш
func (rc *RegexCache) Clear() {
	rc.cache = sync.Map{}
}

// Size возвращает количество кэшированных регулярных выражений
func (rc *RegexCache) Size() int {
	count := 0
	rc.cache.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

func (rc *RegexCache) recordHit() {
	rc.stats.mu.Lock()
	rc.stats.Hits++
	rc.stats.mu.Unlock()
}

func (rc *RegexCache) recordMiss() {
	rc.stats.mu.Lock()
	rc.stats.Misses++
	rc.stats.mu.Unlock()
}
