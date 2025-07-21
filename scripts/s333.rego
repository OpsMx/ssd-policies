package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scan_account = input.metadata.ssd_secret.sonarqube.name

default facetvalues := []
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
facetvalues := response.facets[_].values

info_count := [facetvalues[i].count | facetvalues[i].val == "INFO"]
minor_count := [facetvalues[i].count | facetvalues[i].val == "MINOR"]

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	count(facetvalues) == 0
	msg = "No facet values found for severities."
	sugg = "Kindly check if the Sonarqube token is configured and has permissions to read issues of the project."
	error = "Failed while fetching severity count from Sonarqube."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	count(facetvalues) > 0
	minor_count[0] > 0
	not policy_name in exception_list
	msg = sprintf("Minor issues found during SAST scan for repository %v/%v and branch %v. \nMinor Issues: %v \nInfo Count : %v", [input.metadata.owner, input.metadata.repository, input.metadata.branch, minor_count[0], info_count[0]])
	sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
	error = ""
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus, "accountName": scan_account}]{
	count(facetvalues) > 0
	minor_count[0] > 0
	policy_name in exception_list
	msg = sprintf("Minor issues found during SAST scan for repository %v/%v and branch %v. \nMinor Issues: %v \nInfo Count : %v", [input.metadata.owner, input.metadata.repository, input.metadata.branch, minor_count[0], info_count[0]])
	sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
	error = ""
	alertStatus := "exception"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	count(facetvalues) > 0
	info_count[0] > 0
	not policy_name in exception_list
	msg = sprintf("Minor issues found during SAST scan for repository %v/%v and branch %v. \nMinor Issues: %v \nInfo Count : %v", [input.metadata.owner, input.metadata.repository, input.metadata.branch, minor_count[0], info_count[0]])
	sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
	error = ""
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus, "accountName": scan_account}]{
	count(facetvalues) > 0
	info_count[0] > 0
	policy_name in exception_list
	msg = sprintf("Minor issues found during SAST scan for repository %v/%v and branch %v. \nMinor Issues: %v \nInfo Count : %v", [input.metadata.owner, input.metadata.repository, input.metadata.branch, minor_count[0], info_count[0]])
	sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
	error = ""
	alertStatus := "exception"
}
