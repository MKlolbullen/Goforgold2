package parsers

import (
	"bufio"
	"regexp"
	"strings"

	"recon-tool/main"
)

func ParseDalfoxOutput(output string) []main.VulnerabilityResult {
	var results []main.VulnerabilityResult
	scanner := bufio.NewScanner(strings.NewReader(output))
	re := regexp.MustCompile(`(http[s]?://[^\s]+)`)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "[POC]") {
			match := re.FindStringSubmatch(line)
			if len(match) > 1 {
				results = append(results, main.VulnerabilityResult{
					URL:    match[1],
					Issue:  "XSS",
					Detail: line,
				})
			}
		}
	}
	return results
}
