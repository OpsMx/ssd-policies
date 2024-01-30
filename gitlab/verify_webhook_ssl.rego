package opsmx
import future.keywords.in

default allow = false

request_url = concat("", [input.metadata.ssd_secret.gitlab.rest_api_url,"api/v4/projects/", input.metadata.gitlab_project_id, "/hooks"])

token = input.metadata.ssd_secret.gitlab.token

request = {
    "method": "GET",
    "url": request_url,
    "headers": {
        "PRIVATE-TOKEN": sprintf("%v", [token]),
    },
}

response = http.send(request)

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  response.status_code == 401
  msg := ""
  error := "Unauthorized to check repository webhook configuration due to Bad Credentials."
  sugg := "Kindly check the access token. It must have enough permissions to get webhook configurations."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 404
  msg := ""
  sugg := "Kindly check if the repository provided is correct and the access token has rights to read webhook configuration."
  error := "Mentioned branch for Repository not found while trying to fetch webhook configuration."
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
  error := sprintf("Error %v receieved from Gitlab upon trying to fetch Repository Configuration.", [response.body.message])
  sugg := "Kindly check Gitlab API is reachable and the provided access token has required permissions."
}

default ssl_disabled_hooks = []
ssl_disabled_hooks = [response.body[i].id | response.body[i].enable_ssl_verification == false]

deny[{"alertMsg": msg, "error": error, "suggestion": sugg}]{
  count(ssl_disabled_hooks) > 0
  msg := sprintf("Webhook SSL Check failed: SSL/TLS not enabled for %v/%v repository.", [input.metadata.owner,input.metadata.repository])
  error := ""
  sugg := sprintf("Adhere to the company policy by enabling the webhook ssl/tls for %v/%v repository.", [input.metadata.owner,input.metadata.repository])
}

