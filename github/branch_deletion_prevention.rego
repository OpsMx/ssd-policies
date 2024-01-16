package opsmx

default allow = false

request_components = [input.metadata.rest_url, "repos", input.metadata.github_org, input.metadata.github_repo,"branches",input.metadata.branch,"protection"]
request_url = concat("/", request_components)

token = input.metadata.github_access_token

request = {
    "method": "GET",
    "url": request_url,
    "headers": {
        "Authorization": sprintf("Bearer %v", [token]),
    },
}

response = http.send(request)
raw_body = response.raw_body
parsed_body = json.unmarshal(raw_body)

allow {
  response.status_code = 200
}
deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 404
  msg := ""
  sugg := "Kindly provide the accurate repository name, organization, and branch details"
  error := sprintf("%v %v",[response.status_code,response.body.message])
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 401
  msg := ""
  sugg := "Please provide the Appropriate Git Token for the User"
  error := sprintf("%s %v", [parsed_body.message,response.status])
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 500
  msg := "Internal Server Error"
  sugg := ""
  error := "GitHub is not reachable"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.body.allow_deletions.enabled = true
  msg := sprintf("Github repo %v is having policy and branch cannot be deleted", [input.metadata.github_repo])
  sugg := sprintf("Disable branch deletion in %s Github repo to align with the company policy", [input.metadata.github_repo])
  error := ""
}
