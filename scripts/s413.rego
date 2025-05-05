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

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}] {
	some key
	finding := response.body.ios_api[key]

	finding.metadata.severity == "Medium"
	
	not key in exception_list

	files := concat_keys(finding.files)
	title := sprintf("IOS API Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
	desc := finding.metadata.description
	msg := sprintf("IOS API Analysis Failure in artifact: %v \n Description: %v \n Impacted Files: %v", [artifact_name, desc, files])
	sugg := ""
	error := ""
	alertStatus := "active"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus, "accountName": scan_account}] {
	some key
	finding := response.body.ios_api[key]

	finding.metadata.severity == "Medium"
	
	key in exception_list

	files := concat_keys(finding.files)
	title := sprintf("IOS API Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
	desc := finding.metadata.description
	msg := sprintf("IOS API Analysis Failure in artifact: %v \n Description: %v \n Impacted Files: %v", [artifact_name, desc, files])
	sugg := ""
	error := ""
	exception_cause := key
	alertStatus := "exception"
}

concat_keys(files) = result {
	keys := {k | files[k]}   # Extract the keys from the input object
	result := concat(" \n", keys)  # Join the keys with newline characters
}
