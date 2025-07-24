package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scan_account = input.metadata.ssd_secret.snyk.name

severity = "High"
default findings_count = 0
image_sha = replace(input.metadata.image_sha, ":", "-")

file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codescan_snyk.json"]) {
	input.metadata.source_code_path == ""
}

file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codescan_snyk.json"]) {
	input.metadata.source_code_path != ""
}

complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=snykcodescan"])
download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=snykcodescan"])

request = {	
	"method": "GET",
	"url": complete_url
}

response = http.send(request)

findings_count = count([response.body.snykAnalysis[idx] | response.body.snykAnalysis[idx].severity in ["High", "high"]])
findings = [response.body.snykAnalysis[idx] | response.body.snykAnalysis[idx].severity in ["High", "high"]]

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	findings_count > 0
	some i
	not findings[i].ruleName in exception_list
	rule_name := findings[i].ruleName
	rule_message := findings[i].ruleMessage
    rule_cwe := concat(",", findings[i].cwe)
    locations := [sprintf("%s:%d", [loc.filePath, loc.line]) | loc := findings[i].locations[_]]
    joined_locations := concat(",\n ", locations)
    fixes := concat(",\n ", findings[i].exampleCommitFixes)
	
	title := sprintf("Snyk Code Scan: %v for entity: %v",[findings[i].ruleName, findings[i].ruleMessage])
	msg := sprintf("Snyk Rule Violation found for following rule \n %v: %v \n CWE: %v \n Locations: %v ", [findings[i].ruleName, findings[i].ruleMessage, rule_cwe, joined_locations])
	sugg := sprintf("Please correlate and try following suggested solutions. \n %v", [fixes])
	error := ""
	alertStatus := "active"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus, "accountName": scan_account}]{
	findings_count > 0
	some i
	findings[i].ruleName in exception_list
	rule_name := findings[i].ruleName
	rule_message := findings[i].ruleMessage
    rule_cwe := concat(",", findings[i].cwe)
    locations := [sprintf("%s:%d", [loc.filePath, loc.line]) | loc := findings[i].locations[_]]
    joined_locations := concat(",\n ", locations)
    fixes := concat(",\n ", findings[i].exampleCommitFixes)
	
	title := sprintf("Snyk Code Scan: %v for entity: %v",[findings[i].ruleName, findings[i].ruleMessage])
	msg := sprintf("Snyk Rule Violation found for following rule \n %v: %v \n CWE: %v \n Locations: %v ", [findings[i].ruleName, findings[i].ruleMessage, rule_cwe, joined_locations])
	sugg := sprintf("Please correlate and try following suggested solutions. \n %v", [fixes])
	error := ""
	exception_cause := findings[i].ruleName
	alertStatus := "exception"
}
