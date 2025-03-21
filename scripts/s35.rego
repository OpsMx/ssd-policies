	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default allow = false
	default active_hooks = []
	default active_hooks_count = 0
	default hooks_with_secret = []
	default hooks_with_secret_count = 0

	request_url = concat("/",[input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository, "hooks"])
	token = input.metadata.ssd_secret.github.token
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)

	active_hooks = [response.body[i].config | response.body[i].active == true]
	hooks_with_secret = [response.body[i].config.secret | response.body[i].active == true]

	allow {
		response.status_code = 200
	}


	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := sprintf("Unauthorized to check repository webhook configuration for %s:%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		error := sprintf("401 Unauthorized. Unauthorized to check repository webhook configuration for %s:%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check the access token. It must have enough permissions to get repository webhook configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		error := sprintf("The webhook configuration for Repository %s/%s not found.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository webhook configuration."
		msg := ""
		alertStatus := "error"
	}


	deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking repository webhook configuration for %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := ""
		error := sprintf("Unable to fetch repository webhook configuration. Error %v:%v receieved from Github upon trying to fetch repository webhook configuration.", [response.status_code, response.body.message])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	active_hooks_count = count(active_hooks)
	hooks_with_secret_count = count(hooks_with_secret)
	test = active_hooks_count > hooks_with_secret_count

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		active_hooks_count != 0

		active_hooks_count > hooks_with_secret_count
		policy_name in exception_list
		msg := sprintf("Webhook authentication failed: Secret not set for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by configuring the webhook secret for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		error := ""  
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		active_hooks_count != 0

		active_hooks_count > hooks_with_secret_count
		not policy_name in exception_list
		msg := sprintf("Webhook authentication failed: Secret not set for webhooks in %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by configuring the webhook secret for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		error := ""  
		alertStatus := "active"
	}
