package opsmx

import future.keywords.in

policy_name := input.metadata.policyName
garak_sha256 := replace(input.metadata.image_sha, ":", "-")
scan_account := input.metadata.ssd_secret.garak.name

file_name := concat("", [garak_sha256, "-garakScanResult.json"])

complete_url := concat("", [input.metadata.toolchain_addr, "api/v1/scanResult?fileName=", file_name, "&scanOperation=garakScan"])
download_url := concat("", ["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=garakScan"])

request := {
	"method": "GET",
	"url": complete_url,
}

response := http.send(request)

deny[{"accountName": scan_account, "alertMsg": msg, "alertStatus": alertStatus, "alertTitle": title, "error": error, "exception": "", "fileApi": download_url, "suggestion": sugg}] {
	some i in response.body.Hitlog
	i.probe == policy_name
	title := sprintf("Garak: %v ", [policy_name])
	msg := sprintf("PROBE: %v \n PROMPT: %v \n OUTPUT: %v", [policy_name, i.prompt, i.output])
	sugg := ""
	error := ""
	alertStatus := "active"
}