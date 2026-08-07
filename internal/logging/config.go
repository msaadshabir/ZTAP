package logging

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
