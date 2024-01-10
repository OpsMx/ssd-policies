package opsmx

default allow = false

request_components = [input.metadata.rest_url,"repos", input.metadata.github_org, input.metadata.github_repo,"branches",input.metadata.default_branch]
request_url = concat("/",request_components)

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

message = parsed_body.message

branch_protected = response.body.protected

allow {
  response.status_code = 200
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 404
  msg := "Repo name or Organisation is incorrect"
  sugg := "Please provide the appropriate details"
  error := ""
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 401
  msg := sprintf("Authentication failed for the repo with the error %s", [message])
  sugg := "Incorrect git credentails of the user"
  error := ""
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 500
  msg := "Internal Server Error"
  sugg := "GitHub is not reachable"
  error := ""
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  branch_protected = false
  msg := sprintf("Github repo %v of branch %v is not protected", [input.metadata.github_repo, input.metadata.default_branch])
  sugg := "Please enable the branch protection rules"
  error := ""
}
