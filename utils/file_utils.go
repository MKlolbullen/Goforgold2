package utils

import (
	"encoding/json"
	"os"
	"path/filepath"

	"recon-tool/main" // adjust import if needed
)

func PersistResults(result main.ScanResult, outDir string) error {
	summaryFile := filepath.Join(outDir, "summary.json")
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(summaryFile, data, 0644)
}
