	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_scorecard.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_scorecard.json"]) {
		input.metadata.source_code_path != ""
	}

	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")

	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", file_name, "&", "checkName=", check_name, "&", "scanOperation=", "openssfScan"])

	request = {
		"method": "GET",
		"url": request_url,
	}

	response = http.send(request)


	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.body.code == 404
		msg := ""
		sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
		error := sprintf("Error Received: %v.",[response.body.error])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := ""
		sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
		error := sprintf("Error Received: %v.",[response.body.error])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 302]
		not response.status_code in codes
		msg := ""
		error := sprintf("Error %v receieved: %v", [response.body.error])
		sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
		alertStatus := "error"
	}

	default in_range = false

	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}

	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		in_range == true
		response.body.score < threshold
		not policy_name in exception_list
		documentation := response.body.documentationUrl 
		msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
		sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		in_range == true
		response.body.score < threshold
		policy_name in exception_list
		documentation := response.body.documentationUrl 
		msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
		sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
		error := ""
		alertStatus := "exception"
	}
