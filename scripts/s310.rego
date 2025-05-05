package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scan_account = input.metadata.ssd_secret.trivy.name

default license_count = 0
image_sha = replace(input.metadata.image_sha, ":", "-")

file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codeLicenseScanResult.json"]) {
	input.metadata.source_code_path == ""
}

file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codeLicenseScanResult.json"]) {
	input.metadata.source_code_path != ""
}

complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=codelicensescan"])
download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=codelicensescan"])

request = {	
	"method": "GET",
	"url": complete_url
}

response = http.send(request)
results := response.body.Results

licenses = [response.body.Results[i].Licenses[j] | count(response.body.Results[i].Licenses) > 0]

license_count = count(licenses)

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	license_count == 0
	not policy_name in exception_list
	title := "Code License Scan: No license found."
	msg := sprintf("Code License Scan: No license found to be associated with repository %v:%v.",[input.metadata.owner, input.metadata.repository])
	sugg := "Please associate appropriate license with code repository to be able to evaluate quality of license."
	error := ""
	alertStatus := "active"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus, "accountName": scan_account}]{
	license_count == 0
	policy_name in exception_list
	title := "Code License Scan: No license found."
	msg := sprintf("Code License Scan: No license found to be associated with repository %v:%v.",[input.metadata.owner, input.metadata.repository])
	sugg := "Please associate appropriate license with code repository to be able to evaluate quality of license."
	error := ""
	alertStatus := "exception"
}
