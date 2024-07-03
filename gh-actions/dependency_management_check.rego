package opsmx.dependency_management
import future.keywords.in

# Define a list of trusted sources for dependencies
trusted_sources = [
    "https://registry.npmjs.org/",
    "https://pypi.org/simple/",
    "https://rubygems.org/"
    # Add more trusted sources here
]

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

# Check if the dependencies are fetched from trusted sources
deny[{"alertMsg": msg, "suggestion": sugg, "error": error}] {
    response.status_code == 200

    # Decode the workflow content from base64 and parse as YAML
    workflow_content := base64.decode(response.body.content)
    workflow := yaml.unmarshal(workflow_content)
    job := workflow.jobs[_]
    step := job.steps[_]

    # Check if the step installs dependencies
    step.run
    some dependency in split(step.run, "\n")
    contains(dependency, "install")

    # Verify the source of the dependency
    not is_trusted_source(dependency)

    msg := sprintf("Dependency fetched from untrusted source in step '%s' of job '%s' in workflow '%s'.", [step.name, job.name, input.metadata.ssd_secret.github.workflowName])
    sugg := "Ensure all dependencies are fetched from trusted sources such as npm, PyPI, or RubyGems."
    error := ""
}

# Helper function to check if a dependency is from a trusted source
is_trusted_source(dependency) {
    some trusted_source in trusted_sources
    contains(dependency, trusted_source)
}
