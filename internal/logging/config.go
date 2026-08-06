package logging

import (
	"errors"
	"fmt"
	"os"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

// Config controls structured logging behavior.
type Config struct {
	Level  string `yaml:"level"`
	File   string `yaml:"file"`
	Format string `yaml:"format"`
}

// DefaultConfig returns the default logging configuration.
func DefaultConfig() Config {
	return Config{
		Level:  "info",
		Format: "json",
	}
}

type fileConfig struct {
	Logging Config `yaml:"logging"`
}

// LoadConfig loads logging configuration from the provided YAML file path.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	if strings.TrimSpace(path) == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			applyEnvOverrides(&cfg)
			return cfg, nil
		}
		return cfg, fmt.Errorf("reading config file %s: %w", path, err)
	}

	var fileCfg fileConfig
	if err := yaml.Unmarshal(data, &fileCfg); err != nil {
		return cfg, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	if strings.TrimSpace(fileCfg.Logging.Level) != "" {
		cfg.Level = strings.TrimSpace(fileCfg.Logging.Level)
	}
	if strings.TrimSpace(fileCfg.Logging.File) != "" {
		cfg.File = strings.TrimSpace(fileCfg.Logging.File)
	}
	if strings.TrimSpace(fileCfg.Logging.Format) != "" {
		cfg.Format = strings.TrimSpace(fileCfg.Logging.Format)
	}

	applyEnvOverrides(&cfg)
	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if cfg == nil {
		return
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_LOG_LEVEL")); v != "" {
		cfg.Level = v
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_LOG_FILE")); v != "" {
		cfg.File = v
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_LOG_FORMAT")); v != "" {
		cfg.Format = v
	}
}
