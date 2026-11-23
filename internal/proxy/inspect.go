package proxy

import (
	"bytes"
	"encoding/json"
	"strconv"

	"github.com/roei10101/promptgate/internal/detect"
)

// Violation is a finding located inside a JSON request body. It carries the
// JSON path of the string that matched but never the matched text itself.
type Violation struct {
	Detector string `json:"detector"`
	Path     string `json:"path"`
}

// inspectJSON scans every string value in a JSON document.
//
// It returns the violations it found and a copy of the document in which
// each match is replaced by a redaction marker. ok is false when body is not
// a single valid JSON document; the caller then forwards it untouched.
// Object keys are not scanned.
func inspectJSON(body []byte, detectors []detect.Detector) (violations []Violation, redacted []byte, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	// Keep numbers as written so that re-encoding cannot change them.
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, nil, false
	}
	if dec.More() {
		return nil, nil, false
	}

	doc = walk(doc, "", detectors, &violations)
	if len(violations) == 0 {
		return nil, body, true
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, nil, false
	}
	return violations, bytes.TrimRight(buf.Bytes(), "\n"), true
}

// walk returns v with every string value redacted, appending one violation
// per finding. path is the JSON path of v, e.g. "messages[0].content".
func walk(v any, path string, detectors []detect.Detector, violations *[]Violation) any {
	switch t := v.(type) {
	case string:
		findings := detect.Scan(t, detectors)
		for _, f := range findings {
			*violations = append(*violations, Violation{Detector: f.Detector, Path: path})
		}
		return detect.Redact(t, findings)
	case []any:
		for i, item := range t {
			t[i] = walk(item, path+"["+strconv.Itoa(i)+"]", detectors, violations)
		}
		return t
	case map[string]any:
		for key, item := range t {
			child := key
			if path != "" {
				child = path + "." + key
			}
			t[key] = walk(item, child, detectors, violations)
		}
		return t
	default:
		return v
	}
}
