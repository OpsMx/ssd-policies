package opsmx
import future.keywords.in

default allow = false

request_components = [input.metadata.ssd_secret.bitbucket.rest_api_url,"2.0/repositories", input.metadata.owner, input.metadata.repository]

request_url = concat("/",request_components)

token = input.metadata.ssd_secret.bitbucket.token

request = {
    "method": "GET",
    "url": request_url,
    "headers": {
         "Authorization": sprintf("Bearer %v", [token]),
    },
}

response = http.send(request)

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

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  codes = [401, 404, 500, 200, 301, 302]
  not response.status_code in codes
  msg := "Unable to fetch repository configuration."
  error := sprintf("Error %v:%v receieved from Bitbucket upon trying to fetch Repository Configuration.", [response.status_code, response.body.message])
  sugg := "Kindly check Bitbucket API is reachable and the provided access token has required permissions."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.body.is_private = false
  msg := sprintf("Bitbucket repository is a public repo %v.", [input.metadata.repository])
  sugg := "Please change the repository visibility to private."
  error := ""
}
