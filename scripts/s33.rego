	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_url = concat("/", [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository, "collaborators?affiliation=admin"])

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

	default denial_list = false

	denial_list = matched_users

	matched_users[user] {
		users := [response.body[i].login | response.body[i].type == "User"]
		user := users[_]
		patterns := ["bot", "auto", "test", "jenkins", "drone", "github", "gitlab", "aws", "azure"]
		some pattern in patterns
			regex.match(pattern, user)
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}] {
		counter := count(denial_list)
		counter > 0
		policy_name in exception_list
		denial_list_str := concat(", ", denial_list)
		msg := sprintf("Owner access of Github Repository is granted to bot users. Number of bot users having owner access: %v. Name of bots having owner access: %v", [counter, denial_list_str])
		sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v/%v Repository.", [input.metadata.repository,input.metadata.owner])
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		counter := count(denial_list)
		counter > 0
		policy_name in exception_list
		denial_list_str := concat(", ", denial_list)
		msg := sprintf("Owner access of Github Repository is granted to bot users. Number of bot users having owner access: %v. Name of bots having owner access: %v", [counter, denial_list_str])
		sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v/%v Repository.", [input.metadata.repository,input.metadata.owner])
		error := ""
		alertStatus := "active"
	}
