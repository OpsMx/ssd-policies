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

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	some key
	permission := response.body.permissions[key]
	permission.status == "High"
	not key in exception_list
	info := permission.info
	desc := permission.description
	title := sprintf("Permission: %v assigned to Mobile Application Package: %v", [key, artifact_name])
	msg := sprintf("Permission: %v assigned to Mobile Application Package: %v. \n Permission: %v \n Info: %v \n Description: %v", [key, artifact_name, key, info, desc])
	sugg := ""
	error := ""
	alertStatus := "active"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus, "accountName": scan_account}]{
	some key
	permission := response.body.permissions[key]
	permission.status == "High"
	key in exception_list
	info := permission.info
	desc := permission.description
	title := sprintf("Permission: %v assigned to Mobile Application Package: %v", [key, artifact_name])
	msg := sprintf("Permission: %v assigned to Mobile Application Package: %v. \n Permission: %v \n Info: %v \n Description: %v", [key, artifact_name, key, info, desc])
	sugg := ""
	error := ""
	exception_cause := key
	alertStatus := "exception"
}
