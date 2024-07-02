package opsmx.secure_communication

import future.keywords.in

# Define allowed protocols
allowed_protocols = ["https://", "ssh://"]

# Helper function to check if a URL uses a secure protocol
uses_secure_protocol(url) = true {
    some protocol in allowed_protocols
    startswith(url, protocol)
}

uses_secure_protocol(_) = false

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

# Check if all network communications use secure protocols
deny[{"alertMsg": msg, "step": step, "url": url}] {
    response.status_code == 200

    # Decode the workflow content from base64 and parse as YAML
    workflow_content := base64.decode(response.body.content)
    workflow := yaml.unmarshal(workflow_content)
    job := workflow.jobs[_]
    step := job.steps[_]

    # Check the 'run' field for insecure protocols
    step.run
    some line in split(step.run, "\n")
    url := find_network_calls(line)
    not uses_secure_protocol(url)

    msg := sprintf("Insecure protocol used in step '%s' of job '%s' in workflow '%s'. URL: %v", [step.name, job.name, input.metadata.ssd_secret.github.workflowName, url])
}

# Helper function to extract http URLs from a line of text
find_http_url(line) = url {
    start := indexof(line, "http://")
    start != -1
    rest := substring(line, start, -1)
    end := indexof(rest, " ")
    end == -1
    url := substring(rest, 0, count(rest))
} else {
    start := indexof(line, "http://")
    start != -1
    rest := substring(line, start, -1)
    end := indexof(rest, " ")
    end != -1
    url := substring(rest, 0, end)
}

# Helper function to extract ftp URLs from a line of text
find_ftp_url(line) = url {
    start := indexof(line, "ftp://")
    start != -1
    rest := substring(line, start, -1)
    end := indexof(rest, " ")
    end == -1
    url := substring(rest, 0, count(rest))
} else {
    start := indexof(line, "ftp://")
    start != -1
    rest := substring(line, start, -1)
    end := indexof(rest, " ")
    end != -1
    url := substring(rest, 0, end)
}

# Combined helper function to extract insecure URLs from a line of text
find_network_calls(line) = url {
    url := find_http_url(line)
    url != ""
} else {
    url := find_ftp_url(line)
    url != ""
}
