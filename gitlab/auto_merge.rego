package opsmx
import future.keywords.in

default allow = false
default private_repo = ""

request_components = [input.metadata.ssd_secret.gitlab.rest_api_url,"api/v4/projects", input.metadata.gitlab_project_id, "merge_requests"]

request_url = concat("/",request_components)

token = input.metadata.token

request = {
    "method": "GET",
    "url": request_url,
    "headers": {
        "PRIVATE-TOKEN": sprintf("%v", [token]),
    },
}

response = http.send(request)

allow {
  response.status_code = 200
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  response.status_code == 401
  error := "Unauthorized to check repository branch protection policy configuration due to Bad Credentials."
  msg := ""
  sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 404
  msg := ""
  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository branch protection policy configuration."
  error := "Mentioned branch for Repository not found while trying to fetch repository branch protection policy configuration."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 500
  msg := "Internal Server Error."
  sugg := ""
  error := "GitHub is not reachable."
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  codes = [401, 404, 500, 200, 302]
  not response.status_code in codes
  msg := ""
  error := sprintf("Error %v receieved from Gitlab upon trying to fetch Repository Configuration.", [response.body.message])
  sugg := "Kindly check Gitlab API is reachable and the provided access token has required permissions."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.body.merge_when_pipeline_succeeds = false
  msg := sprintf("Auto Merge is disabled for the repo %v", [input.metadata.repository])
  sugg := "Please change the repository visibility to private."
  error := ""
}
