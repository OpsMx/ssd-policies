package opsmx

import future.keywords.in

default exception_list = []

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scan_account = input.metadata.ssd_secret.zap.name

default issues = []
default count_issues = -1

image_sha = replace(input.metadata.image_sha, ":", "-")

filename = concat("", [input.metadata.projectId, "_", input.metadata.projectName, "_", input.metadata.scanTargetId, "_shannonScan.json"]) {
	input.metadata.scanTargetId != ""
	input.metadata.projectName != ""
	input.metadata.projectId != ""
}

filename = concat("", [image_sha, "_", input.metadata.deploymentId, "_shannonScan.json"]) {
	input.metadata.scanTargetId == ""
	input.metadata.projectName == ""
	input.metadata.projectId == ""
}

complete_url = concat("", [input.metadata.toolchain_addr, "api/v1/scanResult?fileName=", filename, "&scanOperation=shannonpentestscan"])
download_url = concat("", ["tool-chain/api/v1/scanResult?fileName=", filename, "&scanOperation=shannonpentestscan"])

request = {
	"method": "GET",
	"url": complete_url,
}

response = http.send(request)
issues = [response.body.vulnerabilities[i] | response.body.vulnerabilities[i].risk == "Medium"]
count_issues = count(issues)

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}] {
	count_issues == -1
	msg = "Shannon AI Pentest scan results could not be accessed."
	sugg = "Check if the Shannon scan completed successfully and the result file is available in MinIO."
	error = "Failed to fetch Shannon scan results from ToolChain."
	alertStatus := "error"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus, "accountName": scan_account}] {
	count_issues > 0
	some idx
	issues[idx].name in exception_list
	title := sprintf("Shannon AI Pentest: [%v] %v at %v", [issues[idx].category, issues[idx].vulnerabilityType, issues[idx].endpoint])
	msg := build_alert_msg(issues[idx])
	sugg := issues[idx].solution
	error = ""
	exception_cause := issues[idx].name
	alertStatus := "exception"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}] {
	count_issues > 0
	some idx
	not issues[idx].name in exception_list
	title := sprintf("Shannon AI Pentest: [%v] %v at %v", [issues[idx].category, issues[idx].vulnerabilityType, issues[idx].endpoint])
	msg := build_alert_msg(issues[idx])
	sugg := issues[idx].solution
	error = ""
	alertStatus := "active"
}

externally_exploitable_str(vuln) = "Yes" {
	vuln.externallyExploitable == true
}

externally_exploitable_str(vuln) = "No" {
	vuln.externallyExploitable != true
}

loc_parts(code_location) = [file, line] {
	parts := split(code_location, ":")
	count(parts) > 1
	file = concat(":", array.slice(parts, 0, count(parts) - 1))
	line = parts[count(parts) - 1]
}

loc_parts(code_location) = [code_location, ""] {
	parts := split(code_location, ":")
	count(parts) <= 1
}

build_alert_msg(vuln) = msg {
	ee := externally_exploitable_str(vuln)
	lp := loc_parts(vuln.codeLocation)
	parts := [
		sprintf("Vulnerability: %v (%v)", [vuln.vulnerabilityType, vuln.id]),
		sprintf("Category: %v | Confidence: %v | Externally Exploitable: %v", [vuln.category, vuln.confidence, ee]),
		sprintf("Endpoint: %v", [vuln.endpoint]),
		sprintf("Location: %v", [lp[0]]),
		sprintf("Line Number: %v", [lp[1]]),
		sprintf("Description: %v", [vuln.description]),
		sprintf("Exploit Technique: %v", [vuln.exploitTechnique]),
		sprintf("Evidence: %v", [vuln.evidence]),
	]
	msg := concat("\n", parts)
}
