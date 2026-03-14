package engine

import "regexp"

type Rule struct {
	ID       string
	Category string
	Severity string
	Pattern  *regexp.Regexp
	Target   string
}

var Rules = []Rule{
	{
		ID: "SQLI-001", Category: "SQLi", Severity: "CRITICAL", Target: "request",
		Pattern: regexp.MustCompile(`(?i)(union\s+select|information_schema|sleep\s*\(|benchmark\s*\(|drop\s+table|insert\s+into|delete\s+from|update\s+\w+\s+set|exec\s*\(|xp_cmdshell|or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s*or\s*'|--\s*$|;\s*select)`),
	},
	{
		ID: "SQLI-002", Category: "SQLi", Severity: "HIGH", Target: "request",
		Pattern: regexp.MustCompile(`(?i)(\bselect\b.+\bfrom\b|\bwhere\b.+\b(=|like)\b.+('|")|waitfor\s+delay|load_file\s*\(|outfile\s+')`),
	},
	{
		ID: "XSS-001", Category: "XSS", Severity: "HIGH", Target: "request",
		Pattern: regexp.MustCompile(`(?i)(<script[\s>]|<\/script>|javascript\s*:|vbscript\s*:|onload\s*=|onerror\s*=|onclick\s*=|onmouseover\s*=|onfocus\s*=|<iframe[\s>]|<object[\s>]|<embed[\s>])`),
	},
	{
		ID: "XSS-002", Category: "XSS", Severity: "MEDIUM", Target: "request",
		Pattern: regexp.MustCompile(`(?i)(eval\s*\(|expression\s*\(|document\s*\.\s*cookie|document\s*\.\s*write|window\s*\.\s*location|alert\s*\(|confirm\s*\(|prompt\s*\()`),
	},
	{
		ID: "TRAVERSAL-001", Category: "PathTraversal", Severity: "HIGH", Target: "request",
		Pattern: regexp.MustCompile(`(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%252e%252e|\/etc\/passwd|\/etc\/shadow|\/windows\/system32|\/proc\/self)`),
	},
	{
		ID: "CMDI-001", Category: "CommandInjection", Severity: "CRITICAL", Target: "request",
		Pattern: regexp.MustCompile(`(?i)(;\s*(ls|cat|id|whoami|uname|pwd|wget|curl|chmod|rm\s+-|nc\s+|bash|sh\s+-|python|perl|ruby)|&&\s*(ls|cat|id|whoami)|\|\s*(ls|cat|id|whoami|bash)|` + "`" + `[^` + "`" + `]+` + "`" + `|\$\([^)]+\))`),
	},
	{
		ID: "SSRF-001", Category: "SSRF", Severity: "HIGH", Target: "request",
		Pattern: regexp.MustCompile(`(?i)(https?:\/\/(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|0\.0\.0\.0|localhost|::1)|file:\/\/|dict:\/\/|gopher:\/\/|ftp:\/\/127)`),
	},
	{
		ID: "RESP-001", Category: "ResponseLeak", Severity: "MEDIUM", Target: "response",
		Pattern: regexp.MustCompile(`(?i)(stack\s+trace|exception\s+in\s+thread|at\s+[\w\.]+\([\w\.]+\.java:\d+\)|panic:|runtime error:|sql\s+syntax\s+error|mysql_fetch|ORA-\d{5}|microsoft\s+ole\s+db)`),
	},
}
