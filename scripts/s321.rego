package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scan_account = input.metadata.ssd_secret.virustotal.name

default url_count = 0
default suspicious_urls = []
default suspicious_urls_count = 0

image_sha = replace(input.metadata.image_sha, ":", "-")

file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_virustotal_url_scan.json"]) {
	input.metadata.source_code_path == ""
}

file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_virustotal_url_scan.json"]) {
	input.metadata.source_code_path != ""
}

complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=virustotalscan"])
download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=virustotalscan"])

request = {
		"method": "GET",
		"url": complete_url
}

response = http.send(request)
results := response.body.summaryResult
repo_name := response.body.repoName
branch := response.body.branch

suspicious_urls := [results[idx] | results[idx].suspicious > 0]

suspicious_urls_count = count(suspicious_urls)

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	suspicious_urls_count > 0
	some i
	not suspicious_urls[i].url in exception_list
	title := sprintf("Suspicious URL %v found in Repository: %v Branch: %v.", [suspicious_urls[i].url, repo_name, branch])
	msg := sprintf("Suspicious URL %v found in Repository: %v Branch: %v. \nSummary of Scan Results: \nHarmless: %v\nMalicious: %v\nSuspicious: %v\nUndetected: %v\nTimeout: %v",[suspicious_urls[i].url, repo_name, branch, suspicious_urls[i].harmless, suspicious_urls[i].malicious, suspicious_urls[i].suspicious, suspicious_urls[i].undetected, suspicious_urls[i].timeout])
	sugg := "Suggest securing the webhook endpoints from suspicious activities by enabling security measures and remove any unwanted URL references from source code repository and configurations."
	error := ""
	alertStatus := "active"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus, "accountName": scan_account}]{
	suspicious_urls_count > 0
	some i
	suspicious_urls[i].url in exception_list
	title := sprintf("Suspicious URL %v found in Repository: %v Branch: %v.", [suspicious_urls[i].url, repo_name, branch])
	msg := sprintf("Suspicious URL %v found in Repository: %v Branch: %v. \nSummary of Scan Results: \nHarmless: %v\nMalicious: %v\nSuspicious: %v\nUndetected: %v\nTimeout: %v",[suspicious_urls[i].url, repo_name, branch, suspicious_urls[i].harmless, suspicious_urls[i].malicious, suspicious_urls[i].suspicious, suspicious_urls[i].undetected, suspicious_urls[i].timeout])
	sugg := "Suggest securing the webhook endpoints from suspicious activities by enabling security measures and remove any unwanted URL references from source code repository and configurations."
	error := ""
	exception_cause := suspicious_urls[i].url
	alertStatus := "exception"
}
