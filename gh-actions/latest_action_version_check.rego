package opsmx.latest_action_versions

default deny = false

# Define a list of actions and their latest versions
latest_versions = {
    "actions/checkout": "v2",
    "actions/setup-node": "v2",
    "docker/build-push-action": "v2",
    "docker/login-action": "v1"
    # Add more actions and their latest versions here
}

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

# Check if the actions used in the workflow specify a version number and are up-to-date
deny[{"alertMsg": msg, "action": action, "used_version": used_version, "latest_version": latest_version}] {
    response.status_code == 200
    workflow := response.body.jobs[_]
    job := workflow.jobs[_]
    step := job.steps[_]
    
    # Check if the step uses an action
    step.uses
    split_step := split(step.uses, "@")
    action_name := split_step[0]
    used_version := split_step[1]
    
    # Ensure the action specifies a version number
    not contains(step.uses, "@")
    msg := sprintf("Action %v does not specify a version number.", [action_name])
    action := step.uses

    # Ensure the action is using the latest version
    latest_version := latest_versions[action_name]
    used_version != latest_version
    msg := sprintf("Action %v is not using the latest version. Used version: %v, Latest version: %v.", [action_name, used_version, latest_version])
    action := step.uses
}

# Check if response status code is not 200
deny[{"alertMsg": msg, "suggestion": sugg, "error": error}] {
    response.status_code != 200
    msg := "Failed to fetch the workflow."
    error := sprintf("Error %v: %v received from GitHub when trying to fetch the workflow.", [response.status_code, response.body.message])
    sugg := "Ensure the provided GitHub token has the required permissions and the workflow name is correct."
}
