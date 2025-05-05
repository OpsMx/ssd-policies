package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scan_account = input.metadata.ssd_secret.tfsec.name

terraform_repo_url_arr = split(input.metadata.ssd_secret.tfsec.url, "/")
terraform_repo_name = split(terraform_repo_url_arr[count(terraform_repo_url_arr)-1], ".")[0]

deployment_id = input.metadata.deploymentId

image_sha = replace(input.metadata.image_sha, ":", "-")

file_name = concat("", [terraform_repo_name, "_", deployment_id, "_", image_sha, "_tfsecscan.json"])

complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=tfsecscan"])
download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=tfsecscan"])

request = {
		"method": "GET",
		"url": complete_url
}

response = http.send(request)


issues := [response.body.results[idx] |response.body.results[idx].severity == "High"]

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	some issue in issues
	title = issue.rule_description

	not issue.long_id in exception_list

	msg = sprintf("Rule: %v failed during terraform scan of directory %v in Repository %v and Branch %v. Details are: \n Rule ID: %v \n Long Rule ID: %v \n Rule Provider: %v \n Rule Service: %v \n Rule Description: %v \n Impact: %v \n Location: %v:%v:%v", [issue.rule_id, response.body.tfCodeScanDirectory, response.body.repositoryUrl, response.body.branch, issue.rule_id, issue.long_id, issue.rule_provider, issue.rule_service, issue.rule_description, issue.impact, issue.location.filename, issue.location.start_line, issue.location.end_line])
	sugg = sprintf("%v \n Useful Links: %v", [issue.resolution, concat("\n", issue.links)])
	error = ""
	alertStatus = "active"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus, "accountName": scan_account}]{
	some issue in issues
	title = issue.rule_description

	issue.long_id in exception_list

	msg = sprintf("Rule: %v failed during terraform scan of directory %v in Repository %v and Branch %v. Details are: \n Rule ID: %v \n Long Rule ID: %v \n Rule Provider: %v \n Rule Service: %v \n Rule Description: %v \n Impact: %v \n Location: %v:%v:%v", [issue.rule_id, response.body.tfCodeScanDirectory, response.body.repositoryUrl, response.body.branch, issue.rule_id, issue.long_id, issue.rule_provider, issue.rule_service, issue.rule_description, issue.impact, issue.location.filename, issue.location.start_line, issue.location.end_line])
	sugg = sprintf("%v \n Useful Links: %v", [issue.resolution, concat("\n", issue.links)])
	error = ""
	exception_cause = issue.long_id
	alertStatus = "exception"
}
