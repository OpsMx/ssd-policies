package opsmx.approved_actions

default deny = false

# Define a list of approved actions and their versions
approved_actions = {
    "actions/checkout": "v2",
    "actions/setup-node": "v2",
    "docker/build-push-action": "v2",
    "docker/login-action": "v1"
    # Add more approved actions and their versions here
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

# Check if the actions used in the workflow are approved
deny[{"alertMsg": msg, "action": action}] {
    response.status_code == 200
    workflow := response.body.jobs[_]
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
    action := step.uses
}

# Check if response status code is not 200
deny[{"alertMsg": msg, "suggestion": sugg, "error": error}] {
    response.status_code != 200
    msg := "Failed to fetch the workflow."
    error := sprintf("Error %v: %v received from GitHub when trying to fetch the workflow.", [response.status_code, response.body.message])
    sugg := "Ensure the provided GitHub token has the required permissions and the workflow name is correct."
}
