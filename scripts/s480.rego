package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]
scan_account = input.metadata.ssd_secret.pentestgpt.name

default issues = []
default count_issues = -1

filename = concat("", [input.metadata.projectId, "_", input.metadata.projectName, "_", input.metadata.scanTargetId, "_pentestGptScan.json"]) {
    input.metadata.scanTargetId != ""
    input.metadata.projectName != ""
    input.metadata.projectId != ""
}

complete_url = concat("", [input.metadata.toolchain_addr, "api/v1/scanResult?fileName=", filename, "&scanOperation=pentestgptscan"])
download_url = concat("", ["tool-chain/api/v1/scanResult?fileName=", filename, "&scanOperation=pentestgptscan"])

request = {
    "method": "GET",
    "url": complete_url
}

response = http.send(request)

issues = [response.body.vulnerabilities[i] | response.body.vulnerabilities[i].risk == "High"]
count_issues = count(issues)

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scan_account, "alertTitle": ""}] {
    count_issues == -1
    msg = "List of High Severity Issues for PentestGPT Scan could not be accessed."
    sugg = "Kindly check if the PentestGPT is configured properly and SSD has access to the application endpoint."
    error = "Failed while fetching issues from PentestGPT."
    alertStatus := "error"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus, "accountName": scan_account}] {
    count_issues > 0
    some idx
    issues[idx].name in exception_list
    title := sprintf("PentestGPT Scan: %v", [issues[idx].name])
    msg = issues[idx].description
    sugg = issues[idx].solution
    error = ""
    exception_cause := issues[idx].name
    alertStatus := "exception"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}] {
    count_issues > 0
    some idx
    not issues[idx].name in exception_list
    title := sprintf("PentestGPT Scan: %v", [issues[idx].name])
    msg = issues[idx].description
    sugg = issues[idx].solution
    error = ""
    alertStatus := "active"
}