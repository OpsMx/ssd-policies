package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scan_account = input.metadata.ssd_secret.sonarqube.name

default quality_gate_status = ""

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

quality_gate_status := response.body.quality.projectStatus.status

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	quality_gate_status == ""
	msg = "Quality Gate Status for Sonarqube Project could not be accessed."
	sugg = "Kindly check if the Sonarqube token is configured and has permissions to read issues of the project. Also, verify if the quality gates for project are correctly configured."
	error = "Failed while fetching quality gate status from Sonarqube."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	quality_gate_status != ""
	quality_gate_status != "OK"
	not policy_name in exception_list
	msg = sprintf("Quality Gate Status for Sonarqube Project is %v.", [quality_gate_status])
	sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
	error = ""
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus, "accountName": scan_account}]{
	quality_gate_status != ""
	quality_gate_status != "OK"
	policy_name in exception_list
	msg = sprintf("Quality Gate Status for Sonarqube Project is %v.", [quality_gate_status])
	sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
	error = ""
	alertStatus := "exception"
}
