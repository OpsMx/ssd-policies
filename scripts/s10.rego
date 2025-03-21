	package opsmx
	import future.keywords.in

	default allow = false

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	request_components = [input.metadata.ssd_secret.github.url,"orgs", input.metadata.owner, "actions", "permissions", "workflow"]
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
		msg := sprintf("Unauthorized to check Organisation Workflow Permissions for organisation %s due to Bad Credentials.", [input.metadata.owner])
		error := sprintf("401 Unauthorized. Unauthorized to check Workflow Permissions for organisation %s due to Bad Credentials.", [input.metadata.owner])
		sugg := "Kindly check the access token. It must have enough permissions to get organisation workflow permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 404
		msg := "Mentioned Organisation not found while trying to fetch organisation workflow permissions."
		sugg := "Kindly check if the organisation provided is correct."
		error := "Organisation name is incorrect."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.status_code == 500
		msg := "Internal Server Error."
		sugg := ""
		error := sprintf("500 Internal Server Error. Received Error while checking organisation workflow configuration for %s.", [input.metadata.owner])
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		codes = [401, 404, 500, 200, 302]
		not response.status_code in codes
		msg := "Unable to fetch organisation workflow permissions."
		error := sprintf("Error %v:%v receieved from Github upon trying to fetch organisation workflow permissions.", [response.status_code, response.body.message])
		sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
		alertStatus := "error"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.body.default_workflow_permissions != "read"
		policy_name in exception_list
		msg := sprintf("Default workflow permissions for Organisation %v is not set to read.", [input.metadata.owner])
		sugg := sprintf("Adhere to the company policy by enforcing default_workflow_permissions of Organisation %s to read only.", [input.metadata.owner])
		error := ""
		alertStatus := "exception"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.body.default_workflow_permissions != "read"
		not policy_name in exception_list
		msg := sprintf("Default workflow permissions for Organisation %v is not set to read.", [input.metadata.owner])
		sugg := sprintf("Adhere to the company policy by enforcing default_workflow_permissions of Organisation %s to read only.", [input.metadata.owner])
		error := ""
		alertStatus := "active"
	}

