	package opsmx
	import future.keywords.in

	default allow = false

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	outside_collaborators_url = concat("/", [input.metadata.ssd_secret.github.url, "repos", input.metadata.owner, input.metadata.repository, "collaborators?affiliation=outside&per_page=100"])

	request = {
		"method": "GET",
		"url": outside_collaborators_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.github.token]),
		},
	}

	default response = ""
	response = http.send(request)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 401
		error := sprintf("Unauthorized to check repository collaborators for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
		msg := ""
		sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := ""
		sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository collaborators."
		error := "Mentioned branch for Repository not found while trying to fetch repository collaborators. Repo name or Organisation is incorrect."
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
		response.status_code in [200, 301, 302]
		count(response.body) > 0
		not policy_name in exception_list
		collaborators_list = concat(",\n", [response.body[i].login | response.body[i].type == "User"]) 
		msg := sprintf("%v outside collaborators have access to repository. \n The list of outside collaborators is: %v.", [count(response.body), collaborators_list])
		sugg := "Adhere to the company policy by revoking the access of non-organization members for Github repo."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.status_code in [200, 301, 302]
		count(response.body) > 0
		policy_name in exception_list
		collaborators_list = concat(",\n", [response.body[i].login | response.body[i].type == "User"]) 
		msg := sprintf("%v outside collaborators have access to repository. \n The list of outside collaborators is: %v.", [count(response.body), collaborators_list])
		sugg := "Adhere to the company policy by revoking the access of non-organization members for Github repo."
		error := ""
		alertStatus := "exception"
	}
