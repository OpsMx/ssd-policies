package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scan_account = input.metadata.ssd_secret.virustotal.name

image_sha = replace(input.metadata.image_sha, ":", "-")

file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"]) 

complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

request = {	
	"method": "GET",
	"url": complete_url
}

response = http.send(request)

artifact_name := response.body.artifactName

high_severity_certificate_findings := [response.body.certificate_analysis.certificate_findings[i] | response.body.certificate_analysis.certificate_findings[i][0] == "High"]
high_severity_certificate_issue_count := count(high_severity_certificate_findings)

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	high_severity_certificate_issue_count > 0
	some idx in high_severity_certificate_findings
	not idx[2] in exception_list

	title := sprintf("Mobile Application Package Certificate Issue: %v.", [idx[2]])
	msg := idx[1]
	sugg := ""
	error := ""
	alertStatus := "active"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus, "accountName": scan_account}]{
	high_severity_certificate_issue_count > 0
	some idx in high_severity_certificate_findings
	idx[2] in exception_list

	title := sprintf("Mobile Application Package Certificate Issue: %v.", [idx[2]])
	msg := idx[1]
	sugg := ""
	error := ""
	exception_cause := idx[2]
	alertStatus := "exception"
}

