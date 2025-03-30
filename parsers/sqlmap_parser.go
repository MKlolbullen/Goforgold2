package parsers

import (
	"bufio"
	"regexp"
	"strings"

	"recon-tool/main" // adjust import as needed
)

func ParseSqlmapOutput(output string) []main.VulnerabilityResult {
	var results []main.VulnerabilityResult
	scanner := bufio.NewScanner(strings.NewReader(output))
	re := regexp.MustCompile(`(http[s]?://[^\s]+)`)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "is vulnerable") {
			match := re.FindStringSubmatch(line)
			if len(match) > 1 {
				results = append(results, main.VulnerabilityResult{
					URL:    match[1],
					Issue:  "SQL Injection",
					Detail: line,
				})
			}
		}
	}
	return results
}
