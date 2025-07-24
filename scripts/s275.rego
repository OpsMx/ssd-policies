package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scan_account = input.metadata.ssd_secret.trivy.name

default secrets_count = 0

request_url = concat("",[input.metadata.toolchain_addr,"api/", "v1/", "scanResult?fileName="])
image_sha = replace(input.metadata.image_sha, ":", "-")

file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codeScanResult.json"]) {
	input.metadata.source_code_path == ""
}

file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codeScanResult.json"]) {
	input.metadata.source_code_path != ""
}
	
complete_url = concat("", [request_url, file_name, "&scanOperation=codeSecretScan"])
	
request = {
		"method": "GET",
		"url": complete_url
}

response = http.send(request)

secret_results := [response.body.Results[i] | count(response.body.Results[i].Secrets) > 0]

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	secret_results > 0
	some i in secret_results
	secret_file = i.Target

	some j in i.Secrets
	secret_title = j.Title
	not secret_title in exception_list
    secret_severity = j.Severity
	secret_severity == "CRITICAL"
	secret_ruleid = j.RuleID
	secret_start_line = j.StartLine
	secret_end_line = j.EndLine
	secret_highlight = j.Match	

	title := sprintf("Critical Severity Secret detected in code: %v", [secret_title])
	msg := sprintf("Secret found for %v/%v code repository in branch %v.\nSecret identified:\nRule Violated: %v. \nFileName: %v. \nStartLine: %v. \nEnd Line: %v. Highlighted text: %v.", [input.metadata.owner, input.metadata.repository, input.metadata.branch, secret_title, secret_ruleid, secret_file, secret_start_line, secret_end_line, secret_highlight])
    sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
	error := ""
	alertStatus := "active"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "exception": exception_cause, "alertStatus": alertStatus, "accountName": scan_account}]{
	secret_results > 0
	some i in secret_results
	secret_file = i.Target

	some j in i.Secrets
	secret_title = j.Title
	secret_title in exception_list
    secret_severity = j.Severity
	secret_severity == "CRITICAL"
	secret_ruleid = j.RuleID
	secret_start_line = j.StartLine
	secret_end_line = j.EndLine
	secret_highlight = j.Match	

	title := sprintf("Critical Severity Secret detected in code: %v", [secret_title])
	msg := sprintf("Secret found for %v/%v code repository in branch %v.\nSecret identified:\nRule Violated: %v. \nFileName: %v. \nStartLine: %v. \nEnd Line: %v. Highlighted text: %v.", [input.metadata.owner, input.metadata.repository, input.metadata.branch, secret_title, secret_ruleid, secret_file, secret_start_line, secret_end_line, secret_highlight])
    sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
	error := ""
	alertStatus := "exception"
	exception_cause := secret_title
}