package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scan_account = input.metadata.ssd_secret.sonarqube.name

default count_critical_issues = -1

image_sha = replace(input.metadata.image_sha, ":", "-")

file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_sonarqube.json"]) {
	input.metadata.source_code_path == ""
}

file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_", image_sha, "_sonarqube.json"]) {
	input.metadata.source_code_path != ""
}

complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name, "&scanOperation=sonarqubescan"])
download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name ,"&scanOperation=sonarqubescan"] )

request = {
		"method": "GET",
		"url": complete_url
}

response = http.send(request)
critical_issues = response.body.criticalIssues
count_critical_issues = count(critical_issues)

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	count_critical_issues == -1
	msg = "List of Critical Issues for Sonarqube Project could not be accessed."
	sugg = "Kindly check if the Sonarqube token is configured and has permissions to read issues of the project."
	error = "Failed while fetching critical issues from Sonarqube."
	alertStatus := "error"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus, "accountName": scan_account}]{
	count_critical_issues > 0
	some idx
	critical_issues[idx].message in exception_list
	title := sprintf("Sonarqube Scan: %v", [critical_issues[idx].message])
	msg = critical_issues[idx].message
	sugg = "Kindly refer to the suggested resolutions by Sonarqube. For more details about the error, please refer to the detailed scan results."
	error = ""
	exception_cause := critical_issues[idx].message
	alertStatus := "exception"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	count_critical_issues > 0
	some idx
	not critical_issues[idx].message in exception_list
	title := sprintf("Sonarqube Scan: %v", [critical_issues[idx].message])
	msg = critical_issues[idx].message
	sugg = "Kindly refer to the suggested resolutions by Sonarqube. For more details about the error, please refer to the detailed scan results."
	error = ""
	exception_cause := critical_issues[idx].message
	alertStatus := "active"
}
