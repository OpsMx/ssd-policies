package opsmx

import future.keywords.in

policy_name := input.metadata.policyName

scan_account := input.metadata.ssd_secret.modelscan.name

model_sha256= input.metadata.image_sha

file_name := concat("", ["sha256-", model_sha256, "-modelscanScanResult.json"])

complete_url := concat("", [input.metadata.toolchain_addr, "api/v1/scanResult?fileName=", file_name, "&scanOperation=modelscan"])
download_url := concat("", ["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=modelscan"])

request := {
	"method": "GET",
	"url": complete_url,
}

response := http.send(request)
total_issues := response.body.summary.total_issues

scan_targets := {
	"webbrowser": "*", # Includes webbrowser.open()
	"httplib": "*", # Includes http.client.HTTPSConnection()
	"requests.api": "*",
	"aiohttp.client": "*",
}

has_key(obj, key){ 
	obj[key]
}

deny[{"accountName": scan_account, "alertMsg": msg, "alertStatus": alertStatus, "alertTitle": title, "error": error, "exception": "", "fileApi": download_url, "suggestion": sugg}]{
	total_issues > 0
	some i in response.body.issues
	title := sprintf("Modelscan Scan: %v ", [policy_name])
	msg := i.description
	sugg := "Ensure that model files do not contain operators or globals that cannot execute code directly but can still be exploited. These include webbrowser, httplib, request.api, Tensorflow ReadFile, and Tensorflow WriteFile"
	error := ""
	alertStatus := "active"
}