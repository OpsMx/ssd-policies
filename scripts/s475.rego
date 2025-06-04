package opsmx

import future.keywords.in

policy_name := input.metadata.policyName
policy_category := replace(input.metadata.policyCategory, " ", "_")

# TODO:
scan_account := "TBD"

model_file := input.metadata.model_file

# TODO:
file_name := concat("", ["findings_", input.metadata.account, "_", model_file, "_", input.metadata.commit_hash, "_modelscan.json"])

complete_url := concat("", [input.metadata.toolchain_addr, "api/v1/scanResult?fileName=", file_name, "&scanOperation=modelscanScan"])
download_url := concat("", ["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=modelscanScan"])

request := {
	"method": "GET",
	"url": complete_url,
}

response := http.send(request)
total_issues := response.body.summary.total_issues

deny[{"accountName": scan_account, "alertMsg": msg, "alertStatus": alertStatus, "alertTitle": title, "error": error, "exception": "", "fileApi": download_url, "suggestion": sugg}] if {
	total_issues > 0
	some i in response.body.issues
	i.operator == "Lambda"
	title := sprintf("Modelscan Scan: %v ", [policy_name])
	msg := i.description
	sugg := "Ensure that model files do not contain operators or globals that are unsupported by the parent ML library or are known to modelscan. Special caution should be given to Keras Lambda layers, which can be used for arbitrary code execution"
	error := ""
	alertStatus := "active"
}
