	package opsmx
	import future.keywords.in

	default allow = false

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_url = concat("", [input.metadata.ssd_secret.gitlab.url,"api/v4/projects/", input.metadata.gitlab_project_id, "/hooks"])

	token = input.metadata.ssd_secret.gitlab.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"PRIVATE-TOKEN": sprintf("%v", [token]),
		},
	}

	response = http.send(request)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := ""
		error := "Unauthorized to check repository webhook configuration due to Bad Credentials."
		sugg := "Kindly check the access token. It must have enough permissions to get webhook configurations."
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := ""
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read webhook configuration."
		error := "Mentioned branch for Repository not found while trying to fetch webhook configuration."
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := "Gitlab is not reachable."
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 302]
		not response.status_code in codes
		msg := ""
		error := sprintf("Error %v receieved from Gitlab upon trying to fetch Repository Configuration.", [response.body.message])
		sugg := "Kindly check Gitlab API is reachable and the provided access token has required permissions."
		alertStatus := "active"
	}

	default ssl_disabled_hooks = []
	ssl_disabled_hooks = [response.body[i].id | response.body[i].enable_ssl_verification == false]

	deny[{"alertMsg": msg, "error": error, "suggestion": sugg, "exception": "", "alertStatus": alertStatus}]{
		count(ssl_disabled_hooks) > 0
		not policy_name in exception_list
		msg := sprintf("Webhook SSL Check failed: SSL/TLS not enabled for %v/%v repository.", [input.metadata.owner,input.metadata.repository])
		error := ""
		sugg := sprintf("Adhere to the company policy by enabling the webhook ssl/tls for %v/%v repository.", [input.metadata.owner,input.metadata.repository])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "error": error, "suggestion": sugg, "exception": policy_name, "alertStatus": alertStatus}]{
		count(ssl_disabled_hooks) > 0
		policy_name in exception_list
		msg := sprintf("Webhook SSL Check failed: SSL/TLS not enabled for %v/%v repository.", [input.metadata.owner,input.metadata.repository])
		error := ""
		sugg := sprintf("Adhere to the company policy by enabling the webhook ssl/tls for %v/%v repository.", [input.metadata.owner,input.metadata.repository])
		alertStatus := "exception"
	}
