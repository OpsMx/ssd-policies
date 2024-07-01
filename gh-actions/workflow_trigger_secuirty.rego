package opsmx.workflow_trigger_security

default deny = false

# Define allowed branches and events
allowed_branches = ["main", "master", "develop"]
allowed_events = ["push", "pull_request"]

# Construct the request URL to fetch the workflow content
request_components = [input.metadata.ssd_secret.github.rest_api_url, "repos", input.metadata.owner, input.metadata.repository, "actions", "workflows", input.metadata.ssd_secret.github.workflowName]
request_url = concat("/", request_components)

token = input.metadata.ssd_secret.github.token
request = {
    "method": "GET",
    "url": request_url,
    "headers": {
        "Authorization": sprintf("Bearer %v", [token]),
    },
}

response = http.send(request)

# Check if workflows are triggered on allowed branches and events
deny[{"alertMsg": msg, "trigger": trigger}] {
    response.status_code == 200
    workflow := response.body.on

    # Check for disallowed branches in 'push' and 'pull_request' triggers
    (workflow.push or workflow.pull_request)
    some branch in workflow.push.branches
    not branch in allowed_branches
    msg := sprintf("Workflow triggered on disallowed branch '%v' in workflow '%s'.", [branch, input.metadata.ssd_secret.github.workflowName])
    trigger := "branch"

    some branch in workflow.pull_request.branches
    not branch in allowed_branches
    msg := sprintf("Workflow triggered on disallowed branch '%v' in workflow '%s'.", [branch, input.metadata.ssd_secret.github.workflowName])
    trigger := "branch"

    # Check for disallowed events
    some event in keys(workflow)
    not event in allowed_events
    msg := sprintf("Workflow triggered on disallowed event '%v' in workflow '%s'.", [event, input.metadata.ssd_secret.github.workflowName])
    trigger := "event"
}

# Check if the response status code is not 200
deny[{"alertMsg": msg, "suggestion": sugg, "error": error}] {
    response.status_code != 200
    msg := "Failed to fetch the workflow."
    error := sprintf("Error %v: %v received from GitHub when trying to fetch the workflow.", [response.status_code, response.body.message])
    sugg := "Ensure the provided GitHub token has the required permissions and the workflow name is correct."
}
