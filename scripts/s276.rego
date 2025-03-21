	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default secrets_count = 0

	request_url = concat("",[input.metadata.toolchain_addr,"api/", "v1/", "scanResult?fileName="])
	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codeScanResult.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codeScanResult.json"]) {
		input.metadata.source_code_path != ""
	}
		
	complete_url = concat("", [request_url, file_name, "&scanOperation=codeSecretScan"])
	
	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)

	medium_severity_secrets = [response.body.Results[0].Secrets[i].Title | response.body.Results[0].Secrets[i].Severity == "MEDIUM"]
	secrets_count = count(medium_severity_secrets)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		secrets_count > 0
		some i in medium_severity_secrets
		not i in exception_list
		title := sprintf("Medium Severity Secret detected in code: %v", [i])
		msg := sprintf("Secret found for %v/%v code repository in branch %v.\nSecret identified:\n %s", [input.metadata.owner, input.metadata.repository, input.metadata.branch, i])
		sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
		error := ""
		alertStatus := "active"
	}


	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": exception_cause, "alertStatus": alertStatus}]{
		secrets_count > 0
		some i in medium_severity_secrets
		i in exception_list
		title := sprintf("Medium Severity Secret detected in code: %v", [i])
		msg := sprintf("Secret found for %v/%v code repository in branch %v.\nSecret identified:\n %s", [input.metadata.owner, input.metadata.repository, input.metadata.branch, i])
		sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
		error := ""
		alertStatus := "exception"
		exception_cause := i
	}
