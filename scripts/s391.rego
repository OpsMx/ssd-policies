package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0
default low_severity_manifest_issue_count := 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scan_account = input.metadata.ssd_secret.mobsf.name

image_sha = replace(input.metadata.image_sha, ":", "-")

file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

request = {
		"method": "GET",
		"url": complete_url
}

response = http.send(request)


low_severity_manifest_findings = [response.body.manifest_analysis.manifest_findings[idx] | response.body.manifest_analysis.manifest_findings[idx].severity == "Low"]
low_severity_manifest_issue_count = count(low_severity_manifest_findings)
artifact_name := response.body.artifactName

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	some finding in low_severity_manifest_findings
	rule := finding.rule
	rule_title := finding.title
	description := finding.description
	components := concat(",", finding.component)

	not rule in exception_list
	
	title := sprintf("Mobile Application Package Manifest Issue: %v found in %v", [rule, artifact_name])
	msg := sprintf("Mobile Application Package Manifest Issue: %v found in %v. \n Info: %v \n Description: %v \n Components: %v", [rule, artifact_name, rule_title, description, components])
	sugg := ""
	error := ""
	alertStatus := "active"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": rule, "alertStatus": alertStatus, "accountName": scan_account}]{
	some finding in low_severity_manifest_findings
	rule := finding.rule
	rule_title := finding.title
	description := finding.description
	components := concat(",", finding.component)

	rule in exception_list
	
	title := sprintf("Mobile Application Package Manifest Issue: %v found in %v", [rule, artifact_name])
	msg := sprintf("Mobile Application Package Manifest Issue: %v found in %v. \n Info: %v \n Description: %v \n Components: %v", [rule, artifact_name, rule_title, description, components])
	sugg := ""
	error := ""
	alertStatus := "exception"
}
