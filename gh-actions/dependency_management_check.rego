package opsmx.dependency_management

default deny = false

# Define a list of trusted sources for dependencies
trusted_sources = [
    "https://registry.npmjs.org/",
    "https://pypi.org/simple/",
    "https://rubygems.org/"
]

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

# Check if the dependencies are fetched from trusted sources
deny[{"alertMsg": msg, "step": step, "dependency": dependency}] {
    response.status_code == 200
    workflow := response.body.jobs[_]
    job := workflow.jobs[_]
    step := job.steps[_]
    
    # Check if the step installs dependencies
    step.run
    some dependency in split(step.run, "\n")
    dependency_contains := contains(dependency, "install")

    # Verify the source of the dependency
    some trusted_source in trusted_sources
    not contains(dependency, trusted_source)

    msg := sprintf("Dependency fetched from untrusted source in step '%s' of job '%s' in workflow '%s'.", [step.name, job.name, input.metadata.ssd_secret.github.workflowName])
}

# Check if the response status code is not 200
deny[{"alertMsg": msg, "suggestion": sugg, "error": error}] {
    response.status_code != 200
    msg := "Failed to fetch the workflow."
    error := sprintf("Error %v: %v received from GitHub when trying to fetch the workflow.", [response.status_code, response.body.message])
    sugg := "Ensure the provided GitHub token has the required permissions and the workflow name is correct."
}
