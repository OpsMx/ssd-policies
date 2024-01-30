package opsmx
import future.keywords.in

default allow = false
default private_repo = ""

request_url = concat("", [input.metadata.ssd_secret.gitlab.rest_api_url, "api/v4/projects/", input.metadata.gitlab_project_id])

token = input.metadata.ssd_secret.gitlab.token

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
  msg := ""
  error := "Unauthorized to check repository configuration due to Bad Credentials."
  sugg := "Kindly check the access token. It must have enough permissions to get repository configurations."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 404
  msg := ""
  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository configuration."
  error := "Repository not found while trying to fetch Repository Configuration."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 500
  msg := "Internal Server Error."
  sugg := ""
  error := "Gitlab is not reachable."
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  codes = [401, 404, 500, 200, 302]
  not response.status_code in codes
  msg := ""
  error := sprintf("Error %v receieved from Github upon trying to fetch Repository Configuration.", [response.body.message])
  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.body.visibility != "private"
  msg := sprintf("Gitlab Project %v is publically visible.", [input.metadata.repository])
  sugg := "Kindly adhere to security standards and change the visibility of the repository to private."
  error := ""
}
