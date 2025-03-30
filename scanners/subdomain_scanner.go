// scanners/subdomain_scanner.go - Subdomain enumeration using assetfinder and amass.
package scanners

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"time"

	"recon-tool/main"
	"recon-tool/utils"
)

// EnumerateSubdomains runs assetfinder and amass (passive mode) to enumerate subdomains.
func EnumerateSubdomains(target, chaosKey, outDir string, result *main.ScanResult, logFn func(string)) {
	logFn("[*] Starting subdomain enumeration...")

	// Run assetfinder with default parameters.
	assetOut, err := utils.RunCommand("assetfinder", target)
	if err != nil {
		logFn("[!] assetfinder error: " + err.Error())
	}
	// Run amass in passive mode.
	amassOut, err := utils.RunCommand("amass", "enum", "-d", target, "-passive", "-norecursive", "-noalts", "-timeout", "60")
	if err != nil {
		logFn("[!] amass error: " + err.Error())
	}

	allSubs := append(strings.Split(assetOut, "\n"), strings.Split(amassOut, "\n")...)
	allSubs = utils.UniqueStrings(allSubs)
	for _, s := range allSubs {
		if s != "" {
			// For demonstration, assign a dummy IP and ports.
			result.Subdomains = append(result.Subdomains, main.SubdomainResult{
				Hostname: s,
				IP:       "192.0.2.1",
				Ports:    []int{80, 443},
			})
			logFn("[*] Discovered subdomain: " + s)
		}
	}
	// Persist subdomains to file.
	err = utils.WriteLines(allSubs, filepath.Join(outDir, "subdomains.txt"))
	if err != nil {
		logFn("[!] Failed to write subdomains: " + err.Error())
	}
	time.Sleep(1 * time.Second)
}
