package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scan_account = input.metadata.ssd_secret.virustotal.name

default url_count = 0
default malicious_urls = []
default malicious_urls_count = 0

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

malicious_urls := [results[idx] | results[idx].malicious > 0]

malicious_urls_count = count(malicious_urls)

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	malicious_urls_count > 0
	some i
	not malicious_urls[i].url in exception_list
	title := sprintf("Suspicious URL %v found in Repository: %v Branch: %v.", [malicious_urls[i].url, repo_name, branch])
	msg := sprintf("Suspicious URL %v found in Repository: %v Branch: %v. \nSummary of Scan Results: \nHarmless: %v\nMalicious: %v\nSuspicious: %v\nUndetected: %v\nTimeout: %v",[malicious_urls[i].url, repo_name, branch, malicious_urls[i].harmless, malicious_urls[i].malicious, malicious_urls[i].malicious, malicious_urls[i].undetected, malicious_urls[i].timeout])
	sugg := "Suggest securing the webhook endpoints from malicious activities by enabling security measures and remove any unwanted URL references from source code repository and configurations."
	error := ""
	alertStatus := "active"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus, "accountName": scan_account}]{
	malicious_urls_count > 0
	some i
	malicious_urls[i].url in exception_list
	title := sprintf("Suspicious URL %v found in Repository: %v Branch: %v.", [malicious_urls[i].url, repo_name, branch])
	msg := sprintf("Suspicious URL %v found in Repository: %v Branch: %v. \nSummary of Scan Results: \nHarmless: %v\nMalicious: %v\nSuspicious: %v\nUndetected: %v\nTimeout: %v",[malicious_urls[i].url, repo_name, branch, malicious_urls[i].harmless, malicious_urls[i].malicious, malicious_urls[i].malicious, malicious_urls[i].undetected, malicious_urls[i].timeout])
	sugg := "Suggest securing the webhook endpoints from malicious activities by enabling security measures and remove any unwanted URL references from source code repository and configurations."
	error := ""
	exception_cause := malicious_urls[i].url
	alertStatus := "exception"
}
