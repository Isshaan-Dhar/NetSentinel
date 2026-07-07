package engine

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type InspectionResult struct {
	Blocked bool
	Rule    *Rule
	Payload string
}

func InspectRequest(r *http.Request) *InspectionResult {
	targets := collectRequestTargets(r)
	for _, rule := range Rules {
		if rule.Target != "request" {
			continue
		}
		for _, target := range targets {
			if rule.Pattern.MatchString(target) {
				return &InspectionResult{Blocked: true, Rule: &rule, Payload: truncate(target, 512)}
			}
		}
	}
	return &InspectionResult{Blocked: false}
}

func InspectResponse(body []byte) *InspectionResult {
	content := string(body)
	for _, rule := range Rules {
		if rule.Target != "response" {
			continue
		}
		if rule.Pattern.MatchString(content) {
			return &InspectionResult{Blocked: true, Rule: &rule, Payload: truncate(content, 512)}
		}
	}
	return &InspectionResult{Blocked: false}
}

func collectRequestTargets(r *http.Request) []string {
	var targets []string

	// Ensure standard unescaped path is inspected
	targets = append(targets, r.URL.Path)

	// Add RawPath if it contains distinct encoded contents
	if r.URL.RawPath != "" {
		targets = append(targets, r.URL.RawPath)
	}

	targets = append(targets, r.URL.RawQuery)

	decoded, err := url.QueryUnescape(r.URL.RawQuery)
	if err == nil {
		targets = append(targets, decoded)
	}

	for _, vals := range r.URL.Query() {
		for _, v := range vals {
			targets = append(targets, v)
		}
	}

	for _, vals := range r.Header {
		for _, v := range vals {
			targets = append(targets, v)
		}
	}

	// SECURITY & INTEGRITY FIX: Read unconditionally if a body exists, capped at 1MB.
	// Use io.MultiReader to reconstruct the original stream so large file uploads 
	// are not silently truncated and corrupted before reaching the backend.
	if r.Body != nil && r.Body != http.NoBody {
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err == nil {
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(bodyBytes), r.Body))
			targets = append(targets, string(bodyBytes))
		}
	}

	return targets
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max]
	}
	return s
}
