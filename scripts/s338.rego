package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scan_account = input.metadata.ssd_secret.zap.name

default issues = []
default count_issues = -1

image_sha = replace(input.metadata.image_sha, ":", "-")

filename = concat("", [image_sha, "_", input.metadata.deploymentId, "_zapScan.json"]) {
	input.metadata.scanTargetId == ""
    input.metadata.projectName == ""
    input.metadata.projectId == ""
}

filename = concat("", [input.metadata.projectId, "_", input.metadata.projectName, "_", input.metadata.scanTargetId, "_zapScan.json"]) {
	input.metadata.scanTargetId != ""
    input.metadata.projectName != ""
    input.metadata.projectId != ""
}


complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", filename, "&scanOperation=zapDastScan"])
download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", filename, "&scanOperation=zapDastScan"] )

request = {
		"method": "GET",
		"url": complete_url
}

response = http.send(request)
issues = [response.body.zapAlerts[i] | response.body.zapAlerts[i].risk == "Medium"]
count_issues = count(issues)

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	count_issues == -1
	msg = "List of High Severity Issues for OWASP ZAP Scan could not be accessed."
	sugg = "Kindly check if the OWASP ZAP is configured properly and SSD has access to the application endpoint."
	error = "Failed while fetching issues from OWASP ZAP."
	alertStatus := "error"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus, "accountName": scan_account}]{
	count_issues > 0
	some idx
	issues[idx].name in exception_list
	title := sprintf("OWASP ZAP Scan: %v", [issues[idx].name])
	msg = issues[idx].description
	sugg = issues[idx].solution
	error = ""
	exception_cause := issues[idx].name
	alertStatus := "exception"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	count_issues > 0
	some idx
	not issues[idx].name in exception_list
	title := sprintf("OWASP ZAP Scan: %v", [issues[idx].name])
	msg = issues[idx].description
	sugg = issues[idx].solution
	error = ""
	alertStatus := "active"
}
