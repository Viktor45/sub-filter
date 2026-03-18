// main.go
// Пакет main реализует утилиту для фильтрации прокси-подписок.
// Поддерживает два режима работы:
//   - HTTP-сервер для динамической фильтрации (/filter?id=1&c=AD)
//   - CLI-режим для однократной обработки всех подписок (--cli)
package main

import (
	"flag"
	"os"
	"strconv"
	"strings"

	"sub-filter/internal/utils"
	"sub-filter/pkg/config"
	"sub-filter/pkg/logger"
	"sub-filter/pkg/service"
)

func main() {
	// Инициализируем логгер
	logLevel := logger.ParseLevel(os.Getenv("LOG_LEVEL"))
	if logLevel == 0 {
		logLevel = logger.ParseLevel("info")
	}
	log := logger.NewDefault(logLevel)

	var (
		cliMode         = flag.Bool("cli", false, "Run in CLI mode")
		stdout          = flag.Bool("stdout", false, "Print results to stdout (CLI only)")
		configPath      = flag.String("config", "", "Path to config file (YAML/JSON/TOML). Defaults to ./config/config.yaml if not specified.")
		countries       = flag.Bool("countries", false, "Generate ./config/countries.yaml from REST API (CLI only)")
		countryCodesCLI = flag.String("country", "", "Filter by country codes (comma-separated, max 20), e.g. --country=AR,AE")
	)
	flag.Parse()

	defaultConfigPath := "./config/config.yaml"
	if *configPath == "" {
		*configPath = defaultConfigPath
	}

	if *cliMode {
		if *countries {
			utils.GenerateCountries()
			return
		}
		cfg, err := config.Load(*configPath)
		if err != nil {
			log.Error("Failed to load configuration",
				"error", err,
				"configPath", *configPath,
			)
			os.Exit(1)
		}

		// Парсим коды стран
		var parsedCountryCodes []string
		if *countryCodesCLI != "" {
			parsedCountryCodes = strings.Split(*countryCodesCLI, ",")
			for i, code := range parsedCountryCodes {
				parsedCountryCodes[i] = strings.TrimSpace(code)
			}
		}

		// Подготавливаем опции сервиса
		opts := &service.ServiceOptions{
			Sources:         cfg.SourcesMap,
			Rules:           cfg.Rules,
			BadWordRules:    cfg.BadWordRules,
			Countries:       cfg.Countries,
			MaxCountryCodes: cfg.Validation.MaxCountries,
			MaxMergeIDs:     cfg.Validation.MaxMergeIDs,
			MergeBuckets:    cfg.Cache.MergeBuckets,
		}

		// Создаем сервис
		svc, err := service.NewService(cfg, log, opts)
		if err != nil {
			log.Error("Failed to create service", "error", err)
			os.Exit(1)
		}

		// Получаем ИД источников
		var ids []string
		if flag.NArg() > 0 {
			ids = flag.Args()
		} else {
			ids = make([]string, 0, len(cfg.SourcesMap))
			for id := range cfg.SourcesMap {
				ids = append(ids, id)
			}
		}

		// Обрабатываем CLI
		if err := svc.ProcessCLI(ids, parsedCountryCodes, *stdout); err != nil {
			log.Error("CLI processing failed", "error", err)
			os.Exit(1)
		}
		return
	}

	// Нормальный режим работы
	portStr := ""
	if flag.NArg() > 0 {
		portStr = flag.Arg(0)
	} else {
		portStr = "8000"
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("Failed to load configuration",
			"error", err,
			"configPath", *configPath,
		)
		os.Exit(1)
	}

	if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p < 65536 {
		cfg.Server.Port = uint16(p)
	} else {
		cfg.Server.Port = 8000
	}

	// Prepare service options
	opts := &service.ServiceOptions{
		Sources:         cfg.SourcesMap,
		Rules:           cfg.Rules,
		BadWordRules:    cfg.BadWordRules,
		Countries:       cfg.Countries,
		MaxCountryCodes: cfg.Validation.MaxCountries,
		MaxMergeIDs:     cfg.Validation.MaxMergeIDs,
		MergeBuckets:    cfg.Cache.MergeBuckets,
	}

	// Create service
	svc, err := service.NewService(cfg, log, opts)
	if err != nil {
		log.Error("Failed to start server", "error", err)
		os.Exit(1)
	}

	if err := svc.Start(); err != nil {
		log.Error("Failed to start server", "error", err)
		os.Exit(1)
	}
}
