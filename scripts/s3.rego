	package opsmx
	import future.keywords.in

	default allow = false

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.github.url, "repos", input.metadata.owner, input.metadata.repository, "branches", input.metadata.branch, "protection"]
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

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code = 404
		response.body.message != "Branch not protected"
		msg := sprintf("Repository, Branch or Branch Protection Policy not found while trying to fetch Repository Configuration for %s/%s.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check if the repository and branch provided are correct and the access token has rights to read repository configuration. Also, verify if Branch Protection Policy is enabled."
		error := sprintf("Repository, Branch or Branch Protection Policy not found while trying to fetch Repository Configuration for %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 301, 302]
		not response.status_code in codes
		msg := "Unable to fetch repository configuration."
		error := sprintf("Error %v:%v receieved from Github upon trying to fetch Repository Configuration for repository %s/%s.", [response.status_code, response.body.message, input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		msg := sprintf("Unauthorized to check repository configuration for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		error := sprintf("401 Unauthorized. Unauthorized to check repository configuration for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		sugg := "Kindly check the access token. It must have enough permissions to get repository configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking repository configuration for repository %s/%s.", [input.metadata.owner, input.metadata.repository])
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		policy_name in exception_list
		response.body.message == "Branch not protected"
		msg := sprintf("Branch %v of Github repository %v/%v is not protected.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by enforcing Branch Protection Policies for %v/%v Github repository.",[input.metadata.owner, input.metadata.repository])
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": "active"}]{
		not policy_name in exception_list
		response.body.message == "Branch not protected"
		msg := sprintf("Branch %v of Github repository %v/%v is not protected.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy by enforcing Branch Protection Policies for %v/%v Github repository.",[input.metadata.owner, input.metadata.repository])
		error := ""
	}
