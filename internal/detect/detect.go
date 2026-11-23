// Package detect finds sensitive data in text that is about to leave the
// network inside an LLM request.
//
// A Detector reports where a match is, never what it is: findings carry
// offsets and a detector name so callers can redact or block without the
// secret itself ever reaching a log line or an error response.
package detect

import (
	"sort"
	"strings"
)

// Finding is one match of one detector inside a single string.
type Finding struct {
	// Detector is the stable name of the detector that matched,
	// for example "aws_access_key_id".
	Detector string
	// Start and End are byte offsets into the scanned string (End exclusive).
	Start, End int
}

// Detector scans a string and reports every match it recognises.
type Detector interface {
	Name() string
	Scan(s string) []Finding
}

// Scan runs every detector over s and returns the findings ordered by
// position. Findings that overlap an earlier one are dropped, so the result
// is a set of disjoint spans that can be redacted in one pass. When two
// findings start at the same offset the longer one wins.
func Scan(s string, detectors []Detector) []Finding {
	var all []Finding
	for _, d := range detectors {
		all = append(all, d.Scan(s)...)
	}
	if len(all) == 0 {
		return nil
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Start != all[j].Start {
			return all[i].Start < all[j].Start
		}
		return all[i].End > all[j].End
	})
	out := all[:0]
	end := -1
	for _, f := range all {
		if f.Start < end {
			continue
		}
		out = append(out, f)
		end = f.End
	}
	return out
}

// Redact replaces every finding in s with a "[REDACTED:<detector>]" marker.
// The findings must be disjoint and sorted by position, as returned by Scan.
func Redact(s string, findings []Finding) string {
	if len(findings) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	pos := 0
	for _, f := range findings {
		b.WriteString(s[pos:f.Start])
		b.WriteString("[REDACTED:")
		b.WriteString(f.Detector)
		b.WriteString("]")
		pos = f.End
	}
	b.WriteString(s[pos:])
	return b.String()
}
