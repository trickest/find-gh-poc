package extract

import (
	"find-gh-poc/pkg/search"
	"regexp"
	"strings"
)

const (
	CVERegex = "(?i)cve[-–_][0-9]{4}[-–_][0-9]{4,}"
)

type CVEExtractor struct {
	cveRegex *regexp.Regexp
}

func NewCVEExtractor() *CVEExtractor {
	return &CVEExtractor{cveRegex: regexp.MustCompile(CVERegex)}
}

func normalizeCVE(cve string) string {
	normalized := strings.ToUpper(cve)
	normalized = strings.ReplaceAll(normalized, "_", "-")
	normalized = strings.ReplaceAll(normalized, "–", "-")
	return normalized
}

// ExtractCVEsFromReadme extracts CVE IDs from a README file
func (extractor *CVEExtractor) ExtractCVEsFromReadme(readme string) []string {
	ids := make(map[string]bool)
	matches := extractor.cveRegex.FindAllStringSubmatch(readme, -1)
	for _, m := range matches {
		if len(m) > 0 && m[0] != "" {
			normalized := normalizeCVE(m[0])
			ids[normalized] = true
		}
	}

	var result []string
	for id := range ids {
		result = append(result, id)
	}
	return result
}

// ExtractCVEsFromRepository extracts CVE IDs from a repository's URL, description, and topics
func (extractor *CVEExtractor) ExtractCVEsFromRepository(repo search.Repository) []string {
	repoCVEs := make(map[string]bool)

	// Search in URL
	matches := extractor.cveRegex.FindAllStringSubmatch(repo.Url, -1)
	for _, m := range matches {
		if len(m) > 0 && m[0] != "" {
			normalized := normalizeCVE(m[0])
			repoCVEs[normalized] = true
		}
	}

	// Search in description
	matches = extractor.cveRegex.FindAllStringSubmatch(repo.Description, -1)
	for _, m := range matches {
		if len(m) > 0 && m[0] != "" {
			normalized := normalizeCVE(m[0])
			repoCVEs[normalized] = true
		}
	}

	// Search in topics
	for _, topicNode := range repo.RepositoryTopics.Nodes {
		topic := topicNode.Topic.Name
		matches = extractor.cveRegex.FindAllStringSubmatch(topic, -1)
		for _, m := range matches {
			if len(m) > 0 && m[0] != "" {
				normalized := normalizeCVE(m[0])
				repoCVEs[normalized] = true
			}
		}
	}

	var result []string
	for id := range repoCVEs {
		result = append(result, id)
	}
	return result
}
