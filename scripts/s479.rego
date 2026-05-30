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

is_report_errors_policy {
  policy_name == "Jira Xray - Report Errors"
}

deny[{"accountName": scan_account, "alertMsg": msg, "alertStatus": "active", "alertTitle": title, "error": "", "exception": "", "fileApi": download_url, "suggestion": sugg}] {
  is_failed_tests_policy
  some execution in response.body.executions
  some test_run in execution.testRuns
  upper(test_run.status) == "FAILED"
  title := sprintf("Jira Xray Scan: %v", [policy_name])
  msg := sprintf("Test run %v (%v) in execution %v failed with status %v.", [test_run.testIssueKey, test_run.testSummary, execution.jiraKey, test_run.status])
  sugg := "Investigate failed test cases in Jira Xray and fix the failing test scenarios before promotion."
}

deny[{"accountName": scan_account, "alertMsg": msg, "alertStatus": "active", "alertTitle": title, "error": "", "exception": "", "fileApi": download_url, "suggestion": sugg}] {
  is_report_errors_policy
  some err in response.body.errors
  title := sprintf("Jira Xray Scan: %v", [policy_name])
  msg := sprintf("Jira Xray scan reported an execution error: %v", [err])
  sugg := "Resolve Jira Xray execution/reporting errors and rerun the scan to produce a clean report."
}
