package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

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

artifact_name := response.body.artifactName

low_severity_findings := response.body.appsec.Low

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}] {	
	some finding in low_severity_findings

	not finding.title in exception_list

	title := finding.title
	msg := sprintf("Section: %v \n Description: %v", [finding.section, finding.description])
	sugg := ""
	error := ""
	alertStatus := "active"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": title, "alertStatus": alertStatus, "accountName": scan_account}] {
	some finding in low_severity_findings

	finding.title in exception_list
	
	title := finding.title
	msg := sprintf("Section: %v \n Description: %v", [finding.section, finding.description])
	sugg := ""
	error := ""
	alertStatus := "exception"
}
