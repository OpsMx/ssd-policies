	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	severity = "Low"
	default findings_count = 0
	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codescan_snyk.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codescan_snyk.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=snykcodescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=snykcodescan"])

	request = {	
		"method": "GET",
		"url": complete_url
	}

	response = http.send(request)

	findings_count = count([response.body.snykAnalysis[idx] | response.body.snykAnalysis[idx].severity in ["Low", "low"]])
	findings = [response.body.snykAnalysis[idx] | response.body.snykAnalysis[idx].severity in ["Low", "low"]]

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		not findings[i].ruleName in exception_list
		title := sprintf("Snyk Code Scan: %v for entity: %v",[findings[i].ruleName], findings[i].ruleMessage)
		msg := sprintf("Snyk Rule Violation found for following rule \n %v: %v", [findings[i].ruleName, findings[i].ruleMessage])
		sugg := "Please examine the medium severity findings in the Snyk analysis data, available through the View Findings button and proactively review your code for common issues and apply best coding practices during development to prevent such alerts from arising."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		findings_count > 0
		some i
		findings[i].ruleName in exception_list
		title := sprintf("Snyk Code Scan: %v for entity: %v",[findings[i].ruleName, findings[i].ruleMessage])
		msg := sprintf("Snyk Rule Violation found for following rule \n %v: %v", [findings[i].ruleName, findings[i].ruleMessage])
		sugg := "Please examine the medium severity findings in the Snyk analysis data, available through the View Findings button and proactively review your code for common issues and apply best coding practices during development to prevent such alerts from arising."
		error := ""
		exception_cause := findings[i].ruleName
		alertStatus := "exception"
	}
