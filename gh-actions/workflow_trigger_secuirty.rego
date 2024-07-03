package opsmx.workflow_trigger_security

import future.keywords.in

# Define allowed branches and events
allowed_branches = ["main", "master", "develop"]
allowed_events = {"push", "pull_request"}

# Construct the request URL to fetch the workflow content
request_components = [
    input.metadata.ssd_secret.github.rest_api_url,
    "repos",
    input.metadata.owner,
    input.metadata.repository,
    "contents",
    concat("/", ["", ".github", "workflows", input.metadata.ssd_secret.github.workflowName])
]
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

# Check if the response status code is not 200
deny[{"alertMsg": msg, "suggestion": sugg, "error": error}] {
    response.status_code != 200
    msg := "Failed to fetch the workflow."
    error := sprintf("Error %v: %v received from GitHub when trying to fetch the workflow.", [response.status_code, response.body.message])
    sugg := "Ensure the provided GitHub token has the required permissions and the workflow name is correct."
}

# Check if workflows are triggered on allowed branches and events
deny[{"alertMsg": msg, "trigger": trigger}] {
    response.status_code == 200

    # Decode the workflow content from base64 and parse as YAML
    workflow_content := base64.decode(response.body.content)
    workflow := yaml.unmarshal(workflow_content)
    on := workflow.on

    # Check for disallowed branches in 'push' triggers
    some branch in on.push.branches
    not branch in allowed_branches
    msg := sprintf("Workflow triggered on disallowed branch '%v' in 'push' trigger in workflow '%s'.", [branch, input.metadata.ssd_secret.github.workflowName])
    trigger := "branch"
}

deny[{"alertMsg": msg, "trigger": trigger}] {
    response.status_code == 200

    # Decode the workflow content from base64 and parse as YAML
    workflow_content := base64.decode(response.body.content)
    workflow := yaml.unmarshal(workflow_content)
    on := workflow.on

    # Check for disallowed branches in 'pull_request' triggers
    some branch in on.pull_request.branches
    not branch in allowed_branches
    msg := sprintf("Workflow triggered on disallowed branch '%v' in 'pull_request' trigger in workflow '%s'.", [branch, input.metadata.ssd_secret.github.workflowName])
    trigger := "branch"
}

deny[{"alertMsg": msg, "trigger": trigger}] {
    response.status_code == 200

    # Decode the workflow content from base64 and parse as YAML
    workflow_content := base64.decode(response.body.content)
    workflow := yaml.unmarshal(workflow_content)
    on := workflow.on

    # Check for disallowed events
    some event in object.keys(on)
    not event in allowed_events
    msg := sprintf("Workflow triggered on disallowed event '%v' in workflow '%s'.", [event, input.metadata.ssd_secret.github.workflowName])
    trigger := "event"
}
