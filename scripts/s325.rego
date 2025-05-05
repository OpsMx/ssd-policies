package opsmx

import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scm_account = input.metadata.ssd_secret.github.name

# Define allowed branches and events
allowed_branches = ["main", "master", "develop"]
allowed_events = {"push", "pull_request"}

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
deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}] {
	response.status_code != 200
	msg := "Failed to fetch the workflow."
	error := sprintf("Error %v: %v received from GitHub when trying to fetch the workflow.", [response.status_code, response.body.message])
	sugg := "Ensure the provided GitHub token has the required permissions and the workflow name is correct."
	alertStatus := "error"
}

# Check if workflows are triggered on allowed branches and events
deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}] {
	response.status_code == 200

	# Decode the workflow content from base64 and parse as YAML
	workflow_content := base64.decode(response.body.content)
	workflow := yaml.unmarshal(workflow_content)
	on := workflow.on

	# Check for disallowed branches in push triggers
	some branch in on.push.branches
	not branch in allowed_branches
	not policy_name in exception_list
	msg := sprintf("Workflow triggered on disallowed branch %v in push trigger in workflow %s.", [branch, input.metadata.ssd_secret.github.workflowName])
	sugg := "Ensure that the workflow is only triggered on allowed branches: main, master, or develop."
	error := ""
	trigger := "branch"
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}] {
	response.status_code == 200

	# Decode the workflow content from base64 and parse as YAML
	workflow_content := base64.decode(response.body.content)
	workflow := yaml.unmarshal(workflow_content)
	on := workflow.on

	# Check for disallowed branches in push triggers
	some branch in on.push.branches
	not branch in allowed_branches
	policy_name in exception_list
	msg := sprintf("Workflow triggered on disallowed branch %v in push trigger in workflow %s.", [branch, input.metadata.ssd_secret.github.workflowName])
	sugg := "Ensure that the workflow is only triggered on allowed branches: main, master, or develop."
	error := ""
	trigger := "branch"
	alertStatus := "exception"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}] {
	response.status_code == 200

	# Decode the workflow content from base64 and parse as YAML
	workflow_content := base64.decode(response.body.content)
	workflow := yaml.unmarshal(workflow_content)
	on := workflow.on

	# Check for disallowed branches in pull_request triggers
	some branch in on.pull_request.branches
	not branch in allowed_branches
	not policy_name in exception_list
	msg := sprintf("Workflow triggered on disallowed branch %v in pull_request trigger in workflow %s.", [branch, input.metadata.ssd_secret.github.workflowName])
	sugg := "Ensure that the workflow is only triggered on allowed branches: main, master, or develop."
	error := ""
	trigger := "branch"
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}] {
	response.status_code == 200

	# Decode the workflow content from base64 and parse as YAML
	workflow_content := base64.decode(response.body.content)
	workflow := yaml.unmarshal(workflow_content)
	on := workflow.on

	# Check for disallowed branches in pull_request triggers
	some branch in on.pull_request.branches
	not branch in allowed_branches
	policy_name in exception_list
	msg := sprintf("Workflow triggered on disallowed branch %v in pull_request trigger in workflow %s.", [branch, input.metadata.ssd_secret.github.workflowName])
	sugg := "Ensure that the workflow is only triggered on allowed branches: main, master, or develop."
	error := ""
	trigger := "branch"
	alertStatus := "exception"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}] {
	response.status_code == 200

	# Decode the workflow content from base64 and parse as YAML
	workflow_content := base64.decode(response.body.content)
	workflow := yaml.unmarshal(workflow_content)
	on := workflow.on

	# Check for disallowed events
	some event in object.keys(on)
	not event in allowed_events
	not policy_name in exception_list
	msg := sprintf("Workflow triggered on disallowed event %v in workflow %s.", [event, input.metadata.ssd_secret.github.workflowName])
	sugg := "Ensure that the workflow is only triggered on allowed events: push or pull_request."
	error := ""
	trigger := "event"
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}] {
	response.status_code == 200

	# Decode the workflow content from base64 and parse as YAML
	workflow_content := base64.decode(response.body.content)
	workflow := yaml.unmarshal(workflow_content)
	on := workflow.on

	# Check for disallowed events
	some event in object.keys(on)
	not event in allowed_events
	policy_name in exception_list
	msg := sprintf("Workflow triggered on disallowed event %v in workflow %s.", [event, input.metadata.ssd_secret.github.workflowName])
	sugg := "Ensure that the workflow is only triggered on allowed events: push or pull_request."
	error := ""
	trigger := "event"
	alertStatus := "exception"
}
