	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default count_issues = -1
	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codescan_codacy.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codescan_codacy.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=codacyscan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=codacyscan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	issues = response.body.codacyAnalysis
	count_issues = count(issues)

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		count_issues == -1
		msg = "List of Issues for Codacy Project could not be accessed."
		sugg = "Kindly check if the Codacy token is configured and has permissions to read issues of the project."
		error = "Failed while fetching issues from Codacy."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		count(issues) > 0
		some idx
		issues[idx].level == "Warning"
		not policy_name in exception_list
		msg = issues[idx].ruleMessage
		sugg = "Kindly refer to the suggested resolutions by Codacy. For more details about the error, please refer to the detailed scan results."
		error = ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		count(issues) > 0
		some idx
		issues[idx].level == "Warning"
		policy_name in exception_list
		msg = issues[idx].ruleMessage
		sugg = "Kindly refer to the suggested resolutions by Codacy. For more details about the error, please refer to the detailed scan results."
		error = ""
		alertStatus := "exception"
	}
