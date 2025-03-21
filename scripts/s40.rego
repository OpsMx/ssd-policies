	package opsmx
	import future.keywords.in

	default allow = false

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository]
	request_url = concat("/",request_components)

	token = input.metadata.ssd_secret.github.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)
	license_url = response.body.license.url

	allow {
		response.status_code = 200
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		error := sprintf("Unauthorized to check repository configurations for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		msg := ""
		sugg := "Kindly check the access token. It must have enough permissions to get repository configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := ""
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository configurations."
		error := "Mentioned branch for Repository not found while trying to fetch repository configurations. Repo name or Organisation is incorrect."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking repository configurations for %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := "Unable to fetch repository configuration."
		error := sprintf("Error %v:%v receieved from Github upon trying to fetch Repository Configuration.", [response.status_code, response.body.message])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		license_url == null
		not policy_name in exception_list
		msg := sprintf("GitHub License not found for the %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by adding a License file for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		license_url == null
		policy_name in exception_list
		msg := sprintf("GitHub License not found for the %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by adding a License file for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}
