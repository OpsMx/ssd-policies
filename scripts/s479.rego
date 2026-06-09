package opsmx

import future.keywords.in

policy_name := input.metadata.policyName

scan_account := object.get(object.get(input.metadata, "ssd_secret", {}), "jiraxray", {"name": "jiraxray"}).name

test_execution_key := object.get(input.metadata, "testExecutionKey", object.get(input.metadata, "jira_test_execution_key", object.get(input.metadata, "jira_execution_key", "")))
build_id := object.get(input.metadata, "build_id", object.get(input.metadata, "buildId", ""))
artifact_sha := replace(object.get(input.metadata, "image_sha", ""), ":", "-")

file_name := concat("", [test_execution_key, "_", build_id, "_", artifact_sha, "_jiraxray_scan.json"])

complete_url := concat("", [input.metadata.toolchain_addr, "api/v1/scanResult?fileName=", file_name, "&scanOperation=jiraxrayScan"])
download_url := concat("", ["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=jiraxrayScan"])

request := {
  "method": "GET",
  "url": complete_url,
}

response := http.send(request)

is_failed_tests_policy {
  policy_name == "Jira Xray - Failed Test Runs"
}

deny[{"accountName": scan_account, "alertMsg": msg, "alertStatus": "active", "alertTitle": title, "error": error, "exception": "", "fileApi": download_url, "suggestion": sugg}] {
  response.status_code == 404
  title := sprintf("Jira Xray Scan: %v", [policy_name])
  msg := sprintf("Jira Xray scan report not found. Expected file: %v", [file_name])
  error := sprintf("Jira Xray scan result file not found at %v.", [complete_url])
  sugg := "Ensure the Jira Xray scan result is uploaded to the toolchain with the correct file name before policy evaluation."
}

deny[{"accountName": scan_account, "alertMsg": msg, "alertStatus": "active", "alertTitle": title, "error": error, "exception": "", "fileApi": download_url, "suggestion": sugg}] {
  response.status_code == 500
  title := sprintf("Jira Xray Scan: %v", [policy_name])
  msg := "Jira Xray scan result could not be fetched due to a toolchain error."
  error := sprintf("Toolchain returned HTTP 500 when fetching Jira Xray scan result from %v.", [complete_url])
  sugg := "Kindly check if the toolchain service is available in the SSD environment and Jira Xray integration is enabled."
}

deny[{"accountName": scan_account, "alertMsg": msg, "alertStatus": "active", "alertTitle": title, "error": error, "exception": "", "fileApi": download_url, "suggestion": sugg}] {
  codes := [200, 404, 500]
  not response.status_code in codes
  title := sprintf("Jira Xray Scan: %v", [policy_name])
  msg := "Jira Xray scan result could not be fetched."
  error := sprintf("Unexpected HTTP status %v when fetching Jira Xray scan result.", [response.status_code])
  sugg := "Kindly check the toolchain service and Jira Xray integration configuration."
}

deny[{"accountName": scan_account, "alertMsg": msg, "alertStatus": "active", "alertTitle": title, "error": "", "exception": "", "fileApi": download_url, "suggestion": sugg}] {
  response.status_code == 200
  is_failed_tests_policy
  some execution in response.body.executions
  some test_run in execution.testRuns
  upper(test_run.status) in {"FAIL", "FAILED"}
  title := sprintf("Jira Xray Scan: %v", [policy_name])
  msg := sprintf("Test run %v (%v) in execution %v failed with status %v.", [test_run.testIssueKey, test_run.testSummary, execution.jiraKey, test_run.status])
  sugg := "Investigate failed test cases in Jira Xray and fix the failing test scenarios before promotion."
}

