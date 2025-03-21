	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.bitbucket.url,"2.0/workspaces", input.metadata.owner, "permissions/repositories",input.metadata.repository]

	request_url = concat("/",request_components)

	headers = {
		"Authorization": auth_header
	}

	auth_header = sprintf("Basic %s", [base64_encode(concat(":",[username,password]))]) {
		input.metadata.ssd_secret.bitbucket.isBasicAuth
		username = input.metadata.ssd_secret.bitbucket.user
		password = input.metadata.ssd_secret.bitbucket.password
	}

	auth_header = sprintf("Bearer %s", [input.metadata.ssd_secret.bitbucket.token]) {
		not input.metadata.ssd_secret.bitbucket.isBasicAuth
	}


	# Helper function to base64 encode a string
	base64_encode(s) = encoded {
			encoded = base64.encode(s)
	}

	request = {
		"method": "GET",
		"url": request_url,
		"headers": headers,
	}

	response = http.send(request)

	allow {
		response.status_code = 200
	}

	admin = [user |
		user = response.body.values[i];
		user.type == "repository_permission"
		user.permission == "admin"
	]

	admin_users = count(admin)

	all = [user |
		user = response.body.values[i];
		user.type == "repository_permission"
		user.user.type == "user"
	]

	total_users = count(all)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := sprintf("Unauthorized to check permissions for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		error := sprintf("401 Unauthorized. Unauthorized to check permissions for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check the access token. It must have enough permissions to get repository permissions configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := sprintf("Repository %s/%s not found while trying to fetch Repository permissions Configuration.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository permissions configuration."
		error := sprintf("Repository %s/%s not found while trying to fetch Repository permissions Configuration.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking configuration for repository %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := "Unable to fetch repository permissions configuration."
		error := sprintf("Error %v:%v receieved from Bitbucket upon trying to fetch repository permissions configuration.", [response.status_code, response.body.message])
		sugg := "Kindly check Bitbucket API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		admin_percentage = admin_users / total_users * 100

		admin_percentage > 5
		not policy_name in exception_list
		msg := sprintf("More than 5 percentage of total collaborators of %v Bitbucket repository have admin access", [input.metadata.repository])
		sugg := sprintf("Adhere to the company policy and revoke admin access to some users of the repo %v", [input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		admin_percentage = admin_users / total_users * 100

		admin_percentage > 5
		policy_name in exception_list
		msg := sprintf("More than 5 percentage of total collaborators of %v Bitbucket repository have admin access", [input.metadata.repository])
		sugg := sprintf("Adhere to the company policy and revoke admin access to some users of the repo %v", [input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}
