package opsmx

import future.keywords.in

policy_name := input.metadata.policyName
scan_account := input.metadata.ssd_secret.nbdefense.name
model_sha256 = input.metadata.image_sha

file_name := concat("", ["sha256-", model_sha256, "-nbdefenseScanResult.json"])
complete_url := concat("", [input.metadata.toolchain_addr, "api/v1/scanResult?fileName=", file_name, "&scanOperation=nbdefenseScan"])
download_url := concat("", ["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=nbdefenseScan"])

request := {
  "method": "GET",
  "url": complete_url,
}

response := http.send(request)

# 1. SECRETS
deny[{ "accountName": scan_account, "alertMsg": msg, "alertStatus": "active", "alertTitle": title, "error": "", "exception": "", "fileApi": download_url, "suggestion": sugg}] {
  some nb in response.body.notebook_issues
  some issue in nb.issues
  issue.code == "SECRETS"
  msg := sprintf("Secrets found in notebook %v at cell %v", [nb.path, issue.cell.cell_index])
  title := sprintf("NbDefense Secrets Scan: %v", [policy_name])
  sugg := "Remove credentials, tokens, keys, or any secrets from the notebook before pushing."
}

# 2. PII_FOUND
deny[{ "accountName": scan_account, "alertMsg": msg, "alertStatus": "active", "alertTitle": title, "error": "", "exception": "", "fileApi": download_url, "suggestion": sugg}] {
  some nb in response.body.notebook_issues
  some issue in nb.issues
  issue.code == "PII_FOUND"
  types := [k | k := issue.details.summary_field[_]]
  msg := sprintf("Notebook '%v' contains PII in cell %v: %v", [nb.path, issue.cell.cell_index, types])
  title := sprintf("NbDefense PII Scan: %v", [policy_name])
  sugg := "Scrub or remove sensitive information like PERSON, LOCATION, SSN, EMAIL from notebook cells before pushing."
}

# 3. UNAPPROVED_LICENSE_IMPORT
deny[{ "accountName": scan_account, "alertMsg": msg, "alertStatus": "active", "alertTitle": title, "error": "", "exception": "", "fileApi": download_url, "suggestion": sugg}] {
  some nb in response.body.notebook_issues
  some issue in nb.issues
  issue.code == "UNAPPROVED_LICENSE_IMPORT"
  msg := sprintf("Notebook '%v' contains code with unapproved license: %v", [nb.path, issue.details.license])
  title := sprintf("NbDefense License Scan (Import): %v", [policy_name])
  sugg := "Replace or remove dependencies using unapproved licenses from code imports."
}

# 4. LICENSE_NOT_FOUND_NOTEBOOK
deny[{ "accountName": scan_account, "alertMsg": msg, "alertStatus": "active", "alertTitle": title, "error": "", "exception": "", "fileApi": download_url, "suggestion": sugg }] {
  some nb in response.body.notebook_issues
  some issue in nb.issues
  issue.code == "LICENSE_NOT_FOUND_NOTEBOOK"
  msg := sprintf("Notebook '%v' contains code with unknown license in cell %v", [nb.path, issue.cell.cell_index])
  title := sprintf("NbDefense License Scan (Unknown): %v", [policy_name])
  sugg := "Verify open-source components and annotate their licenses explicitly."
}

# 5. LICENSE_NOT_FOUND_DEP_FILE
deny[{ "accountName": scan_account, "alertMsg": msg, "alertStatus": "active", "alertTitle": title, "error": "", "exception": "", "fileApi": download_url, "suggestion": sugg }] {
  some nb in response.body.notebook_issues
  some issue in nb.issues
  issue.code == "LICENSE_NOT_FOUND_DEP_FILE"
  msg := sprintf("Notebook '%v' contains code with unknown license in cell %v", [nb.path, issue.cell.cell_index])
  title := sprintf("NbDefense License Scan (Dependency File): %v", [policy_name])
  sugg := "Verify open-source components and annotate their licenses explicitly."
}