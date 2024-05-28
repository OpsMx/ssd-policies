package opsmx

default allow = false

request_components = [input.metadata.ssd_secret.github.rest_api_url, "repos", input.metadata.owner, input.metadata.repository, "actions/variables"]

request_url = concat("/", request_components)

token = input.metadata.ssd_secret.github.token

request = {
    "method": "GET",
    "url": request_url,
    "headers": {
        "Authorization": sprintf("Bearer %v", [token])
    }
}

response = http.send(request)
variables_check = response.body.total_count

allow {
  response.status_code = 200
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  response.status_code == 401
  msg := "Unauthorized to check repository configuration due to Bad Credentials."
  error := "401 Unauthorized."
  sugg := "Kindly check the access token. It must have enough permissions to get repository configurations."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 404
  msg := "Repository not found while trying to fetch Repository Configuration."
  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository configuration."
  error := "Repo name or Organisation is incorrect."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 500
  msg := "Internal Server Error."
  sugg := ""
  error := "GitHub is not reachable."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  variables_check == 1
  msg := sprintf("Repository Variables are configured for the Github repo %v/%v repository", [input.metadata.owner, input.metadata.repository])
  sugg := sprintf("Adhere to the company policy by adding the repository variables for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
  error := ""
}
