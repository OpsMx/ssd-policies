package opsmx

import rego.v1

mock_vulnerabilities := [
	{
		"id": "AUTH-VULN-01",
		"name": "AUTH-VULN-01: Token_Management_Issue",
		"category": "auth",
		"vulnerabilityType": "Token_Management_Issue",
		"risk": "High",
		"description": "Flask SECRET_KEY is hardcoded as 'dev'",
		"solution": "Generate a cryptographically random SECRET_KEY",
		"endpoint": "POST /xben-001-24/",
		"codeLocation": "app/__init__.py:13",
		"exploitTechnique": "session_fixation",
		"confidence": "High",
		"externallyExploitable": true,
		"evidence": "Verified SECRET_KEY value in source code",
	},
	{
		"id": "AUTH-VULN-02",
		"name": "AUTH-VULN-02: Weak_Session_Management",
		"category": "auth",
		"vulnerabilityType": "Weak_Session_Management",
		"risk": "Medium",
		"description": "Session cookies lack Secure and HttpOnly flags",
		"solution": "Set Secure and HttpOnly flags on all session cookies",
		"endpoint": "GET /xben-001-24/login",
		"codeLocation": "app/auth.py:45",
		"exploitTechnique": "session_hijacking",
		"confidence": "Medium",
		"externallyExploitable": true,
		"evidence": "Cookie headers inspected in HTTP response",
	},
	{
		"id": "AUTHZ-VULN-01",
		"name": "AUTHZ-VULN-01: Horizontal",
		"category": "authz",
		"vulnerabilityType": "Horizontal",
		"risk": "High",
		"description": "No authorization check on user profile endpoint",
		"solution": "Implement per-user authorization checks on profile access",
		"endpoint": "GET /xben-001-24/profile/2",
		"codeLocation": "app/views.py:88-92",
		"exploitTechnique": "idor",
		"confidence": "High",
		"externallyExploitable": true,
		"evidence": "Accessed user 2 profile with user 1 session token",
	},
	{
		"id": "AUTH-VULN-03",
		"name": "AUTH-VULN-03: Missing_Rate_Limiting",
		"category": "auth",
		"vulnerabilityType": "Missing_Rate_Limiting",
		"risk": "Low",
		"description": "No rate limiting on login endpoint",
		"solution": "Add rate limiting to authentication endpoints",
		"endpoint": "POST /xben-001-24/login",
		"codeLocation": "app/auth.py:12",
		"exploitTechnique": "brute_force",
		"confidence": "Medium",
		"externallyExploitable": true,
		"evidence": "100 login attempts with no throttling observed",
	},
]

# Override response to avoid real HTTP call
response := {"status_code": 200, "body": {
	"target": "http://target.example.com",
	"status": "completed",
	"vulnerabilities": mock_vulnerabilities,
}}

# Provide input.metadata matching what ssd-opa feeds into OPA
mock_input := {"metadata": {
	"toolchain_addr": "http://tool-chain:8100/",
	"image_sha": "sha256:abc123",
	"deploymentId": "dep-001",
	"isOpenApiSpec": "",
	"projectId": "",
	"projectName": "",
	"scanTargetId": "",
	"policyName": "Shannon AI Pentest Scan High Risk Policy",
	"policyCategory": "DAST",
	"policySeverity": "High",
	"ssd_secret": {"zap": {"name": "whitebox-account"}},
	"exception": {},
}}

# --- High Risk Policy Tests ---

test_high_risk_generates_alerts_for_high_vulns if {
	alerts := deny with input as mock_input
	count(alerts) == 2
}

test_high_risk_alert_title_includes_category_and_type if {
	alerts := deny with input as mock_input
	titles := {a.alertTitle | some a in alerts}
	some t in titles
	contains(t, "Token_Management_Issue")
}

test_high_risk_alert_title_includes_authz_vuln if {
	alerts := deny with input as mock_input
	titles := {a.alertTitle | some a in alerts}
	some t in titles
	contains(t, "Horizontal")
}

test_high_risk_alert_msg_contains_exploit_technique if {
	alerts := deny with input as mock_input
	some a in alerts
	contains(a.alertTitle, "Token_Management_Issue")
	contains(a.alertMsg, "session_fixation")
}

test_high_risk_alert_msg_contains_code_location if {
	alerts := deny with input as mock_input
	some a in alerts
	contains(a.alertTitle, "Token_Management_Issue")
	contains(a.alertMsg, "app/__init__.py:13")
}

test_high_risk_alert_msg_contains_externally_exploitable if {
	alerts := deny with input as mock_input
	some a in alerts
	contains(a.alertTitle, "Token_Management_Issue")
	contains(a.alertMsg, "Externally Exploitable: Yes")
}

test_high_risk_alert_msg_contains_evidence if {
	alerts := deny with input as mock_input
	some a in alerts
	contains(a.alertTitle, "Token_Management_Issue")
	contains(a.alertMsg, "Verified SECRET_KEY value in source code")
}

test_high_risk_alert_msg_contains_endpoint if {
	alerts := deny with input as mock_input
	some a in alerts
	contains(a.alertTitle, "Token_Management_Issue")
	contains(a.alertMsg, "POST /xben-001-24/")
}

test_high_risk_suggestion_is_missing_defense if {
	alerts := deny with input as mock_input
	some a in alerts
	contains(a.alertTitle, "Token_Management_Issue")
	a.suggestion == "Generate a cryptographically random SECRET_KEY"
}

test_high_risk_excludes_medium_vulns if {
	alerts := deny with input as mock_input
	every a in alerts {
		not contains(a.alertTitle, "AUTH-VULN-02")
	}
}

test_high_risk_excludes_low_vulns if {
	alerts := deny with input as mock_input
	every a in alerts {
		not contains(a.alertTitle, "AUTH-VULN-03")
	}
}

test_high_risk_alert_has_file_api if {
	alerts := deny with input as mock_input
	some a in alerts
	contains(a.fileApi, "shannonpentestscan")
}

test_high_risk_alert_has_account_name if {
	alerts := deny with input as mock_input
	some a in alerts
	a.accountName == "whitebox-account"
}

test_high_risk_no_alerts_on_empty_body if {
	empty_response := {"status_code": 200, "body": {"vulnerabilities": []}}
	alerts := deny with input as mock_input with response as empty_response
	count(alerts) == 0
}

test_high_risk_no_alerts_when_no_high_vulns if {
	only_medium := {"status_code": 200, "body": {"vulnerabilities": [mock_vulnerabilities[1]]}}
	alerts := deny with input as mock_input with response as only_medium
	count(alerts) == 0
}

# --- Adhoc scan filename test ---

test_adhoc_scan_filename_uses_project_fields if {
	adhoc_input := json.patch(mock_input, [
		{"op": "replace", "path": "/metadata/projectId", "value": "0x2c934ea"},
		{"op": "replace", "path": "/metadata/projectName", "value": "benchmark-app"},
		{"op": "replace", "path": "/metadata/scanTargetId", "value": "0xabc123"},
	])
	alerts := deny with input as adhoc_input
	some a in alerts
	contains(a.fileApi, "0x2c934ea_benchmark-app_0xabc123_shannonScan.json")
}
