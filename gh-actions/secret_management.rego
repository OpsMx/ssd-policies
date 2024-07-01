package opsmx.secret_management

default deny = false

# Define sensitive keywords to look for in the workflow
sensitive_keywords = ["API_KEY", "SECRET_KEY", "PASSWORD", "TOKEN"]

# Helper function to check if a string contains any sensitive keyword
contains_sensitive_keyword(value) = true {
    some keyword in sensitive_keywords
    contains(value, keyword)
}

contains_sensitive_keyword(_) = false

# Construct the request URL to fetch the workflow content
request_components = [input.metadata.ssd_secret.github.rest_api_url, "repos", input.metadata.owner, input.metadata.repository, "actions", "workflows", input.metadata.ssd_secret.github.workflowName, "runs"]
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

# Check if any step contains hardcoded sensitive data
deny[{"alertMsg": msg, "suggestion": sugg, "step": step}] {
    response.status_code == 200
    workflow := response.body.jobs[_]
    job := workflow.jobs[_]
    step := job.steps[_]

    # Check the 'run' field for hardcoded sensitive data
    step.run
    contains_sensitive_keyword(step.run)

    msg := sprintf("Hardcoded sensitive data found in step '%s' of job '%s' in workflow '%s'.", [step.name, job.name, input.metadata.ssd_secret.github.workflowName])
    sugg := "Reference sensitive data using GitHub Secrets instead of hardcoding them in the workflow."
}

# Check if any 'with' field contains hardcoded sensitive data
deny[{"alertMsg": msg, "suggestion": sugg, "step": step}] {
    response.status_code == 200
    workflow := response.body.jobs[_]
    job := workflow.jobs[_]
    step := job.steps[_]

    some key, value in step.with
    contains_sensitive_keyword(value)

    msg := sprintf("Hardcoded sensitive data found in 'with' field of step '%s' of job '%s' in workflow '%s'.", [step.name, job.name, input.metadata.ssd_secret.github.workflowName])
    sugg := "Reference sensitive data using GitHub Secrets instead of hardcoding them in the workflow."
}

# Check if response status code is not 200
deny[{"alertMsg": msg, "suggestion": sugg, "error": error}] {
    response.status_code != 200
    msg := "Failed to fetch the workflow."
    error := sprintf("Error %v: %v received from GitHub when trying to fetch the workflow.", [response.status_code, response.body.message])
    sugg := "Ensure the provided GitHub token has the required permissions and the workflow name is correct."
}
