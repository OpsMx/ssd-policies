package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scan_account = input.metadata.ssd_secret.semgrep.name

severity = "low"
default findings_count = 0

image_sha = replace(input.metadata.image_sha, ":", "-")

file_name = concat("", ["findings_", input.metadata.owner, "_", input.metadata.repository, "_", severity, "_", input.metadata.build_id, "_semgrep.json"]) {
	input.metadata.source_code_path == ""
}

file_name = concat("", ["findings_", input.metadata.owner, "_", input.metadata.repository, "_", severity, "_", input.metadata.build_id, "_", image_sha, "_semgrep.json"]) {
	input.metadata.source_code_path != ""
}

complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=semgrepScan"])
download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=semgrepScan"])

request = {	
		"method": "GET",
		"url": complete_url
}

response = http.send(request)

findings_count = response.body.totalFindings
findings = response.body.findings

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	findings_count > 0
	some i
	title := sprintf("Semgrep Scan: %v ",[findings[i].rule_name])
	not findings[i].rule_name in exception_list	
	fix = findings[i].fix
	owasp = concat(", ", findings[i].owasp)
	cwe = concat(", ", findings[i].cwe)
	file = findings[i].location.file_path
	line = findings[i].location.line
	msg := sprintf("%v: %v \n\n OWASP Rule Violations: %v \n CWE: %v \n Location: %v \n Line Number: %v", [findings[i].rule_name, findings[i].rule_message, owasp, cwe, file, line])
	sugg := sprintf("Please correlate and incorporate following suggested solution: \n %v", [fix])
	error := ""
	alertStatus := "active"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus, "accountName": scan_account}]{
	findings_count > 0
	some i
	title := sprintf("Semgrep Scan: %v ",[findings[i].rule_name])
	findings[i].rule_name in exception_list
	fix = findings[i].fix
	owasp = concat(", ", findings[i].owasp)
	cwe = concat(", ", findings[i].cwe)
	file = findings[i].location.file_path
	line = findings[i].location.line
	msg := sprintf("%v: %v \n\n OWASP Rule Violations: %v \n CWE: %v \n Location: %v \n Line Number: %v", [findings[i].rule_name, findings[i].rule_message, owasp, cwe, file, line])
	sugg := sprintf("Please correlate and incorporate following suggested solution: \n %v", [fix])
	error := ""
	exception_cause := findings[i].rule_name
	alertStatus := "exception"
}