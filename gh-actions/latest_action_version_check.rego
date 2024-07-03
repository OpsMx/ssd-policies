package opsmx.latest_action_versions

import future.keywords.in

# Define a list of actions and their latest versions
latest_versions = {
    "actions/checkout": "v2",
    "actions/setup-node": "v2",
    "docker/build-push-action": "v2",
    "docker/login-action": "v1"
    # Add more actions and their latest versions here
}

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

# Check if the actions used in the workflow specify a version number
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
    
    # Ensure the action specifies a version number
    not contains(step.uses, "@")
    msg := sprintf("Action %v does not specify a version number.", [action_name])
    action := step.uses
    sugg := "Specify the version number for the action in the format action_name@version."
    error := ""
}

# Check if the actions used in the workflow are up-to-date
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
    used_version := split_step[1]
    
    # Ensure the action is using the latest version
    latest_version := latest_versions[action_name]
    used_version != latest_version
    msg := sprintf("Action %v is not using the latest version. Used version: %v, Latest version: %v.", [action_name, used_version, latest_version])
    action := step.uses
    sugg := "Update the action to the latest version listed in the policy."
    error := ""
}
