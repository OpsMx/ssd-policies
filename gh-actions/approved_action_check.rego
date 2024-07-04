package opsmx.approved_actions
import future.keywords.in

# Define a list of approved actions and their versions
approved_actions = {
    "actions/checkout": "v2",
    "actions/setup-node": "v2",
    "docker/build-push-action": "v2",
    "docker/login-action": "v1"
    # Add more approved actions and their versions here
}

# Construct the request URL to list all workflows
list_workflows_url = sprintf("%s/repos/%s/%s/actions/workflows", [
    input.metadata.ssd_secret.github.rest_api_url,
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
    input.metadata.ssd_secret.github.rest_api_url,
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
deny[{"alertMsg": msg, "suggestion": sugg, "error": error}] {
    response.status_code != 200
    msg := "Failed to fetch the workflow."
    error := sprintf("Error %v: %v received from GitHub when trying to fetch the workflow.", [response.status_code, response.body.message])
    sugg := "Ensure the provided GitHub token has the required permissions and the workflow name is correct."
}

# Check if the actions used in the workflow are approved
deny[{"alertMsg": msg, "suggestion": sugg, "error": error}] {
    response.status_code == 200

    # Decode the workflow content from base64 and parse as YAML
    workflow_content := base64.decode(response.body.content)
    workflow := yaml.unmarshal(workflow_content)
    job := workflow.jobs[_]
    step := job.steps[_]
    
    # Check if the step uses an action
    step.uses
    split_step := split(step.uses, "@")
    action_name := split_step[0]
    action_version := split_step[1]
    
    # Ensure the action is in the approved list
    not approved_actions[action_name] == action_version
    
    msg := sprintf("Action %v@%v is not from an approved source or version.", [action_name, action_version])
    sugg := "Update the action to an approved version listed in the policy, or contact the repository owner to approve the current version."
    error := ""
}
