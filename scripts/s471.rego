package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0
	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	severity = "low"
	default findings_count = 0

	image_sha = replace(input.metadata.image_sha, ":", "-")
	file_name = concat("", ["findings_", input.metadata.owner, "_", input.metadata.repository, "_", severity, "_", input.metadata.build_id, "_opengrep.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["findings_", input.metadata.owner, "_", input.metadata.repository, "_", severity, "_", input.metadata.build_id, "_", image_sha, "_opengrep.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=opengrepScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=opengrepScan"])

	request = {	
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	findings_count = response.body.totalFindings
	findings = response.body.findings

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		title := sprintf("Opengrep Scan: %v ",[findings[i].rule_name])
		not findings[i].rule_name in exception_list
		msg := sprintf("%v: %v", [findings[i].rule_name, findings[i].rule_message])
		sugg := "Please examine the low-severity findings in the OPENGREP analysis data, available through the View Findings button and proactively review your code for common issues and apply best coding practices during development to prevent such alerts from arising."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		title := sprintf("Opengrep Scan: %v ",[findings[i].rule_name])
		findings[i].rule_name in exception_list
		msg := sprintf("%v: %v", [findings[i].rule_name, findings[i].rule_message])
		sugg := "Please examine the low-severity findings in the OPENGREP analysis data, available through the View Findings button and proactively review your code for common issues and apply best coding practices during development to prevent such alerts from arising."
		error := ""
		exception_cause := findings[i].rule_name
		alertStatus := "exception"
	}
