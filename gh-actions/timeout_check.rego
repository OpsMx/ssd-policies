package opsmx.timeout_settings

import future.keywords.in

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

# Check if each job has a timeout configured
deny[{"alertMsg": msg, "suggestion": sugg, "error": error}] {
    response.status_code == 200

    # Decode the workflow content from base64 and parse as YAML
    workflow_content := base64.decode(response.body.content)
    workflow := yaml.unmarshal(workflow_content)
    jobs := workflow.jobs

    some job_name in jobs
    job := jobs[job_name]
    not job["timeout-minutes"]

    msg := sprintf("Job '%s' in workflow '%s' does not have a timeout configured.", [job_name, input.metadata.ssd_secret.github.workflowName])
    sugg := "Configure a timeout for the job in the workflow file."
    error := ""
}

# Check if each step has a timeout configured (if applicable)
deny[{"alertMsg": msg, "suggestion": sugg, "error": error}] {
    response.status_code == 200

    # Decode the workflow content from base64 and parse as YAML
    workflow_content := base64.decode(response.body.content)
    workflow := yaml.unmarshal(workflow_content)
    jobs := workflow.jobs

    some job_name in jobs
    job := jobs[job_name]
    steps := job.steps

    some step_name in steps
    step := steps[step_name]
    not step["timeout-minutes"]

    msg := sprintf("Step '%s' in job '%s' of workflow '%s' does not have a timeout configured.", [step_name, job_name, input.metadata.ssd_secret.github.workflowName])
    sugg := "Configure a timeout for the step in the workflow file."
    error := ""
}
