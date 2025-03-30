// /scanners/fuzzing_scanner.go - Fuzzing with ffuf using a wordlist.
package scanners

import (
	"bufio"
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"recon-tool/main"
	"recon-tool/utils"
	"strings"
)

// RunFuzzing runs ffuf with a default wordlist to find hidden endpoints.
func RunFuzzing(target, outDir string, result *main.ScanResult, logFn func(string)) {
	logFn("[*] Running ffuf fuzzing...")
	ffufOut := filepath.Join(outDir, "ffuf_results.json")
	// Execute ffuf with default parameters.
	_, err := utils.RunCommand("ffuf",
		"-w", "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt:FUZZ",
		"-u", "http://"+target+"/FUZZ",
		"-of", "json", "-o", ffufOut)
	if err != nil {
		logFn("[!] ffuf error: " + err.Error())
		return
	}
	// Parse ffuf results.
	data, err := ioutil.ReadFile(ffufOut)
	if err != nil {
		logFn("[!] Failed to read ffuf output: " + err.Error())
		return
	}
	var ffufResults []main.FfufResult
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		var entry main.FfufResult
		if err := json.Unmarshal([]byte(scanner.Text()), &entry); err == nil {
			ffufResults = append(ffufResults, entry)
		}
	}
	result.FfufEntries = ffufResults
	logFn(fmt.Sprintf("[*] ffuf fuzzing completed, found %d entries", len(ffufResults)))
}
