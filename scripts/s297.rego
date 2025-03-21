	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.bitbucket.url,"2.0/repositories", input.metadata.owner, input.metadata.repository, "branch-restrictions"]

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

	branch_protect = [response.body.values[i]| response.body.values[i].type == "branchrestriction"]

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := sprintf("Unauthorized to check branch protection policy configuration for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		error := sprintf("401 Unauthorized. Unauthorized to check repository configuration for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := sprintf("Repository %s/%s not found while trying to fetch Repository branch protection policy Configuration.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository branch protection policy configuration."
		error := sprintf("Repository %s/%s not found while trying to fetch Repository branch protection policy Configuration.", [input.metadata.owner, input.metadata.repository])
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
		msg := "Unable to fetch repository branch protection policy configuration."
		error := sprintf("Error %v:%v receieved from Bitbucket upon trying to fetch repository branch protection policy configuration.", [response.status_code, response.body.message])
		sugg := "Kindly check Bitbucket API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.body.size == 0
		not policy_name in exception_list
		msg := sprintf("Branch %v of Bitbucket repository %v/%v is not protected by branch protection policies.", [input.metadata.branch, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by enforcing Branch Protection Policy for branches of %v Bitbucket repository.",[input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.body.size == 0
		policy_name in exception_list
		msg := sprintf("Branch %v of Bitbucket repository %v/%v is not protected by branch protection policies.", [input.metadata.branch, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by enforcing Branch Protection Policy for branches of %v Bitbucket repository.",[input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		count(branch_protect) == 0
		not policy_name in exception_list
		msg := sprintf("Branch %v of Bitbucket repository %v/%v is not protected by branch protection policies.", [input.metadata.branch, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by enforcing Branch Protection Policy for branches of %v Bitbucket repository.",[input.metadata.repository])
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		count(branch_protect) == 0
		policy_name in exception_list
		msg := sprintf("Branch %v of Bitbucket repository %v/%v is not protected by branch protection policies.", [input.metadata.branch, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by enforcing Branch Protection Policy for branches of %v Bitbucket repository.",[input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}
