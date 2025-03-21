	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default allow = false

	request_components = [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository, "collaborators"]
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

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		error := sprintf("Unauthorized to check repository collaborators for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		msg := ""
		sugg := "Kindly check the access token. It must have enough permissions to get repository collaborators."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := ""
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository collaborators."
		error := "Mentioned branch for Repository not found while trying to fetch repository collaborators."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking repository collaborators for %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := ""
		error := sprintf("Unable to fetch repository collaborators. Error %v:%v receieved from Github.", [response.status_code, response.body.message])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}


	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		admins = [response.body[i].login | response.body[i].role_name == "admin"]
		total_users = count(response.body[i])
		admin_users = count(admins)
		admin_percentage = admin_users / total_users * 100

		admin_percentage > 5
		not policy_name in exception_list
		msg := sprintf("More than 5 percentage of total collaborators of %v github repository have admin access", [input.metadata.repository])
		sugg := sprintf("Adhere to the company policy and revoke admin access to some users of the repo %v", [input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		admins = [response.body[i].login | response.body[i].role_name == "admin"]
		total_users = count(response.body[i])
		admin_users = count(admins)
		admin_percentage = admin_users / total_users * 100

		admin_percentage > 5
		policy_name in exception_list
		msg := sprintf("More than 5 percentage of total collaborators of %v github repository have admin access", [input.metadata.repository])
		sugg := sprintf("Adhere to the company policy and revoke admin access to some users of the repo %v", [input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}
