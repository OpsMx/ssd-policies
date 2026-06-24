package opsmx

import rego.v1

mock_vulnerabilities := [
	{
		"id": "AUTH-VULN-01", "name": "AUTH-VULN-01: Token_Management_Issue",
		"category": "auth", "vulnerabilityType": "Token_Management_Issue",
		"risk": "High", "description": "Hardcoded SECRET_KEY",
		"solution": "Randomize SECRET_KEY", "endpoint": "POST /app/",
		"codeLocation": "app/__init__.py:13", "exploitTechnique": "session_fixation",
		"confidence": "High", "externallyExploitable": true, "evidence": "Verified in source",
	},
	{
		"id": "AUTH-VULN-02", "name": "AUTH-VULN-02: Weak_Session_Management",
		"category": "auth", "vulnerabilityType": "Weak_Session_Management",
		"risk": "Medium", "description": "Missing Secure and HttpOnly flags",
		"solution": "Set cookie flags", "endpoint": "GET /app/login",
		"codeLocation": "app/auth.py:45", "exploitTechnique": "session_hijacking",
		"confidence": "Medium", "externallyExploitable": true, "evidence": "Cookie inspection",
	},
	{
		"id": "AUTH-VULN-03", "name": "AUTH-VULN-03: Missing_Rate_Limiting",
		"category": "auth", "vulnerabilityType": "Missing_Rate_Limiting",
		"risk": "Low", "description": "No rate limiting",
		"solution": "Add rate limiting", "endpoint": "POST /app/login",
		"codeLocation": "app/auth.py:12", "exploitTechnique": "brute_force",
		"confidence": "Medium", "externallyExploitable": true, "evidence": "100 attempts observed",
	},
]

response := {"status_code": 200, "body": {
	"target": "http://target.example.com",
	"status": "completed",
	"vulnerabilities": mock_vulnerabilities,
}}

mock_input := {"metadata": {
	"toolchain_addr": "http://tool-chain:8100/",
	"image_sha": "sha256:abc123",
	"deploymentId": "dep-001",
	"isOpenApiSpec": "",
	"projectId": "", "projectName": "", "scanTargetId": "",
	"policyName": "Shannon AI Pentest Scan Medium Risk Policy",
	"policyCategory": "DAST", "policySeverity": "Medium",
	"ssd_secret": {"zap": {"name": "whitebox-account"}},
	"exception": {},
}}

test_medium_risk_generates_one_alert if {
	alerts := deny with input as mock_input
	count(alerts) == 1
}

test_medium_risk_matches_only_medium_vulns if {
	alerts := deny with input as mock_input
	some a in alerts
	contains(a.alertTitle, "Weak_Session_Management")
}

test_medium_risk_excludes_high_vulns if {
	alerts := deny with input as mock_input
	every a in alerts {
		not contains(a.alertTitle, "Token_Management_Issue")
	}
}

test_medium_risk_excludes_low_vulns if {
	alerts := deny with input as mock_input
	every a in alerts {
		not contains(a.alertTitle, "Missing_Rate_Limiting")
	}
}

test_medium_risk_alert_msg_has_full_context if {
	alerts := deny with input as mock_input
	some a in alerts
	contains(a.alertMsg, "session_hijacking")
	contains(a.alertMsg, "app/auth.py:45")
	contains(a.alertMsg, "Externally Exploitable: Yes")
}
