package opsmx

import future.keywords.in

policy_name := input.metadata.policyName

# TODO: Verify
scan_account := input.metadata.ssd_secret.garak.name

# TODO: Redefine when things finalize
file_name := concat("", ["findings_", input.metadata.account, "_", input.metadata.model_name, "_garak.json"])

complete_url := concat("", [input.metadata.toolchain_addr, "api/v1/scanResult?fileName=", file_name, "&scanOperation=garakScan"])
download_url := concat("", ["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=garakScan"])

request := {
	"method": "GET",
	"url": complete_url,
}

response := http.send(request)

deny[{"accountName": scan_account, "alertMsg": msg, "alertStatus": alertStatus, "alertTitle": title, "error": error, "exception": "", "fileApi": download_url, "suggestion": sugg}] if {
	some i in response.body
	i.probe == policy_name
	title := sprintf("Garak: %v ", [policy_name])
	msg := sprintf("PROBE: %v \n PROMPT: %v \n OUTPUT: %v", [policy_name, i.prompt, i.output])
	sugg := ""
	error := ""
	alertStatus := "active"
}
