package opsmx
import future.keywords.in

default allow = false
default active_hooks = []
default active_hooks_count = 0
default hooks_with_secret = []
default hooks_with_secret_count = 0

request_url = concat("/",[input.metadata.ssd_secret.github.rest_api_url,"repos", input.metadata.owner, input.metadata.repository, "hooks"])
token = input.metadata.ssd_secret.github.token
request = {
    "method": "GET",
    "url": request_url,
    "headers": {
        "Authorization": sprintf("Bearer %v", [token]),
    },
}

response = http.send(request)

active_hooks = [response.body[i].config | response.body[i].active == true]
hooks_with_secret = [response.body[i].config.secret | response.body[i].active == true]

allow {
  response.status_code = 200
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  response.status_code == 401
  msg := ""
  error := "401 Unauthorized: Unauthorized to check repository webhook configuration due to Bad Credentials."
  sugg := "Kindly check the access token. It must have enough permissions to get repository webhook configurations."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 404
  msg := ""
  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository webhook configuration."
  error := "Mentioned branch for Repository not found while trying to fetch repository webhook configuration. Repo name or Organisation is incorrect."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 500
  msg := "Internal Server Error."
  sugg := ""
  error := "GitHub is not reachable."
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  codes = [401, 404, 500, 200, 301, 302]
  not response.status_code in codes
  msg := ""
  error := sprintf("Unable to fetch repository webhook configuration. Error %v:%v receieved from Github upon trying to fetch repository webhook configuration.", [response.status_code, response.body.message])
  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
}

active_hooks_count = count(active_hooks)
hooks_with_secret_count = count(hooks_with_secret)

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  active_hooks_count != 0

  active_hooks_count > hooks_with_secret_count
  msg := sprintf("Webhook authentication failed: Secret not set for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
  sugg := sprintf("Adhere to the company policy by configuring the webhook secret for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
  error := ""  
}
