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
	"__builtin__": [
		"eval",
		"compile",
		"getattr",
		"apply",
		"exec",
		"open",
		"breakpoint",
		"__import__",
	], # Pickle versions 0, 1, 2 have those function under '__builtin__'
	"builtins": [
		"eval",
		"compile",
		"getattr",
		"apply",
		"exec",
		"open",
		"breakpoint",
		"__import__",
	], # Pickle versions 3, 4 have those function under 'builtins'
	"runpy": "*",
	"os": "*",
	"nt": "*", # Alias for 'os' on Windows. Includes os.system()
	"posix": "*", # Alias for 'os' on Linux. Includes os.system()
	"socket": "*",
	"subprocess": "*",
	"sys": "*",
	"operator": ["attrgetter"], # Ex of code execution: operator.attrgetter("system")(__import__("os"))("echo pwned")
	"pty": "*",
	"pickle": "*",
	"_pickle": "*",
	"bdb": "*",
	"pdb": "*",
	"shutil": "*",
	"asyncio": "*",
}

check_for_star(op){
	op == "*"
}

check_for_specific_op(op, module) {
	not scan_targets[module] == "*"
	op in scan_targets[module]
}

has_key(obj, key) {
 obj[key]
}

deny[{"accountName": scan_account, "alertMsg": msg, "alertStatus": alertStatus, "alertTitle": title, "error": error, "exception": "", "fileApi": download_url, "suggestion": sugg}] {
	total_issues > 0
	some i in response.body.issues
	title := sprintf("Modelscan Scan: %v ", [policy_name])
	msg := i.description
	sugg := "Ensure that model files do not contain operators or globals that can execute code. These operators include exec, eval, runpy, sys, open, breakpoint, os, subprocess, socket, nt, posix."
	error := ""
	alertStatus := "active"
}

deny[{"accountName": scan_account, "alertMsg": msg, "alertStatus": alertStatus, "alertTitle": title, "error": error, "exception": "", "fileApi": download_url, "suggestion": sugg}] {
	total_issues > 0
	some i in response.body.issues
	title := sprintf("Modelscan Scan: %v ", [policy_name])
	msg := i.description
	sugg := "Ensure that model files do not contain operators or globals that can execute code. These operators include exec, eval, runpy, sys, open, breakpoint, os, subprocess, socket, nt, posix."
	error := ""
	alertStatus := "active"
}