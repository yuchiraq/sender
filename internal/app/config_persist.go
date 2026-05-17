package app

import "fmt"

func SaveConfig(path string, cfg Config) error {
	cfg.BaseDir = ""
	if err := saveJSONAtomic(path, cfg); err != nil {
		return fmt.Errorf("не удалось сохранить конфиг: %w", err)
	}
	return nil
}
