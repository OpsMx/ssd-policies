package opsmx

import future.keywords.in

policy_name := input.metadata.policyName
scan_account := input.metadata.ssd_secret.nbdefense.name
model_sha256 := input.metadata.image_sha
policy_severity := input.metadata.policySeverity

file_name := concat("", ["sha256-", model_sha256, "-nbdefenseScanResult.json"])
complete_url := concat("", [input.metadata.toolchain_addr, "api/v1/scanResult?fileName=", file_name, "&scanOperation=nbdefenseScan"])
download_url := concat("", ["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=nbdefenseScan"])

request := {
  "method": "GET",
  "url": complete_url,
}

response := http.send(request)

# 1. UNAPPROVED_LICENSE_DEP_FILE
deny[{ "accountName": scan_account, "alertMsg": msg, "alertStatus": "active", "alertTitle": title, "error": "", "exception": "", "fileApi": download_url, "suggestion": sugg }] {
  some dep in response.body.dependency_issues
  dep.code == "UNAPPROVED_LICENSE_DEP_FILE"
  
  msg := sprintf("Unapproved license '%v' found in dependency: %v", [dep.details.license, dep.details.library])
  title := sprintf("NbDefense License Scan (Dependency File): %v", [policy_name])
  sugg := "Use only dependencies with approved licenses. Replace or remove unapproved ones."
}

# 2. DEPENDENCY_FILE (general dependency file issue)
deny[{ "accountName": scan_account, "alertMsg": msg, "alertStatus": "active", "alertTitle": title, "error": "", "exception": "", "fileApi": download_url, "suggestion": sugg }] {
  some dep in response.body.dependency_issues
  dep.code == "DEPENDENCY_FILE"
 
  msg := sprintf("Potential risk in dependency file: %v", [dep.details.library])
  title := sprintf("NbDefense Dependency File Issue: %v", [policy_name])
  sugg := "Review dependency file manually for unverified or unused libraries."
}

# 3. VULNERABLE_DEPENDENCY_DEP_FILE (filtered by severity)
deny[{ "accountName": scan_account, "alertMsg": msg, "alertStatus": "active", "alertTitle": title, "severity": dep.details.severity,"error": "", "exception": "", "fileApi": download_url, "suggestion": sugg }] {
  some dep in response.body.dependency_issues
  dep.code == "VULNERABLE_DEPENDENCY_DEP_FILE"
  upper(dep.details.severity) == upper(policy_severity)

  msg := sprintf("Known CVE in dependency: %v (CVE: %v, Severity: %v)", [dep.details.library, dep.details.cve, dep.details.severity])
  title := sprintf("NbDefense CVE Dependency Issue: %v", [policy_name])
  sugg := "Upgrade or remove vulnerable dependency to avoid security risk."
}

# 4. VULNERABLE_DEPENDENCY_IMPORT (filtered by severity)
deny[{ "accountName": scan_account, "alertMsg": msg, "alertStatus": "active", "alertTitle": title, "severity": dep.details.severity,"error": "", "exception": "", "fileApi": download_url, "suggestion": sugg }] {
  some dep in response.body.dependency_issues
  dep.code == "VULNERABLE_DEPENDENCY_IMPORT"
  upper(dep.details.severity) == upper(policy_severity)

  msg := sprintf("Vulnerable library '%v' imported in notebook. CVE: %v, Severity: %v", [dep.details.library, dep.details.cve, dep.details.severity])
  title := sprintf("NbDefense CVE Import Risk: %v", [policy_name])
  sugg := "Remove or patch imported vulnerable libraries to prevent potential exploits."
}