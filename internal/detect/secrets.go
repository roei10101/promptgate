package detect

import "regexp"

// regexDetector reports every match of a regular expression.
type regexDetector struct {
	name string
	re   *regexp.Regexp
}

func (d regexDetector) Name() string { return d.name }

func (d regexDetector) Scan(s string) []Finding {
	locs := d.re.FindAllStringIndex(s, -1)
	if len(locs) == 0 {
		return nil
	}
	out := make([]Finding, 0, len(locs))
	for _, loc := range locs {
		out = append(out, Finding{Detector: d.name, Start: loc[0], End: loc[1]})
	}
	return out
}

// Secrets returns the built-in credential detectors.
//
// Every pattern targets a format with a fixed, vendor-specific prefix or
// structure. That keeps false positives low enough for the gateway to block
// on a match: there is deliberately no generic "high-entropy string" rule.
func Secrets() []Detector {
	return []Detector{
		// Long-term (AKIA) and temporary (ASIA) AWS access key IDs.
		regexDetector{"aws_access_key_id", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
		// Classic GitHub tokens: personal (ghp), OAuth (gho), user-to-server
		// (ghu), server-to-server (ghs) and refresh (ghr).
		regexDetector{"github_token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`)},
		// Fine-grained GitHub personal access tokens.
		regexDetector{"github_token", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,255}`)},
		// Slack bot, user, app, refresh and legacy tokens.
		regexDetector{"slack_token", regexp.MustCompile(`\bxox[abeprs]-[A-Za-z0-9-]{10,}`)},
		// API keys in the "sk-" family used by several LLM providers.
		regexDetector{"llm_api_key", regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`)},
		// JSON Web Tokens: three base64url segments, the first two of which
		// are JSON objects and therefore start with "eyJ".
		regexDetector{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},
		// PEM private keys. The match runs to the END line, or to the end of
		// the string when the key is truncated, so no key material survives.
		regexDetector{"private_key", regexp.MustCompile(
			`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\z)`)},
	}
}
