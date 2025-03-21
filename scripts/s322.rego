	package opsmx

	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	# Define sensitive keywords to look for in the workflow
	sensitive_keywords = ["API_KEY", "SECRET_KEY", "PASSWORD", "TOKEN"]

	# Helper function to check if a string contains any sensitive keyword
	contains_sensitive_keyword(value) = true {
		some keyword in sensitive_keywords
		contains(value, keyword)
	}

	contains_sensitive_keyword(_) = false

	# Construct the request URL to list all workflows
	list_workflows_url = sprintf("%s/repos/%s/%s/actions/workflows", [
		input.metadata.ssd_secret.github.url,
		input.metadata.owner,
		input.metadata.repository
	])

	token = input.metadata.ssd_secret.github.token
	list_workflows_request = {
		"method": "GET",
		"url": list_workflows_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	list_workflows_response = http.send(list_workflows_request)

	# Find the workflow by name
	workflow_file_path = workflow_path {
		some workflow in list_workflows_response.body.workflows
		workflow.name == input.metadata.ssd_secret.github.workflowName
		workflow_path := workflow.path
	}

	# Construct the request URL to fetch the workflow content
	request_url = sprintf("%s/repos/%s/%s/contents/%s", [
		input.metadata.ssd_secret.github.url,
		input.metadata.owner,
		input.metadata.repository,
		workflow_file_path
	])

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}

	response = http.send(request)

	# Check if the response status code is not 200
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.status_code != 200
		msg := "Failed to fetch the workflow."
		error := sprintf("Error %v: %v received from GitHub when trying to fetch the workflow.", [response.status_code, response.body.message])
		sugg := "Ensure the provided GitHub token has the required permissions and the workflow name is correct."
		alertStatus := "error"
	}

	# Check if any step contains hardcoded sensitive data
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		response.status_code == 200

		# Decode the workflow content from base64 and parse as YAML
		workflow_content := base64.decode(response.body.content)
		workflow := yaml.unmarshal(workflow_content)
		job := workflow.jobs[_]
		step := job.steps[_]

		# Check the run field for hardcoded sensitive data
		step.run
		contains_sensitive_keyword(step.run)
		not policy_name in exception_list

		msg := sprintf("Hardcoded sensitive data found in step %s of job %s in workflow %s.", [step.name, job.name, input.metadata.ssd_secret.github.workflowName])
		sugg := "Reference sensitive data using GitHub Secrets instead of hardcoding them in the workflow."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}] {
		response.status_code == 200

		# Decode the workflow content from base64 and parse as YAML
		workflow_content := base64.decode(response.body.content)
		workflow := yaml.unmarshal(workflow_content)
		job := workflow.jobs[_]
		step := job.steps[_]

		# Check the run field for hardcoded sensitive data
		step.run
		contains_sensitive_keyword(step.run)
		policy_name in exception_list

		msg := sprintf("Hardcoded sensitive data found in step %s of job %s in workflow %s.", [step.name, job.name, input.metadata.ssd_secret.github.workflowName])
		sugg := "Reference sensitive data using GitHub Secrets instead of hardcoding them in the workflow."
		error := ""
		alertStatus := "exception"
	}
