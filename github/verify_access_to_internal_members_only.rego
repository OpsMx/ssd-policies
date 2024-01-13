package opsmx
import future.keywords.in

default allow = false

outside_collaborators_url = concat("/", [input.metadata.ssd_secret.github.rest_api_url, "repos", input.metadata.owner, input.metadata.repository, "collaborators?affiliation=outside&per_page=100"])

request = {
    "method": "GET",
    "url": outside_collaborators_url,
    "headers": {
        "Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.github.token]),
    },
}

default response = ""
response = http.send(request)

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  response.status_code == 401
  msg := ""
  error := "401 Unauthorized: Unauthorized to check repository collaborators."
  sugg := "Kindly check the access token. It must have enough permissions to get repository collaborators."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 404
  msg := ""
  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository collaborators."
  error := "Mentioned branch for Repository not found while trying to fetch repository collaborators. Repo name or Organisation is incorrect."
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
  error := sprintf("Unable to fetch repository collaborators. Error %v:%v receieved from Github.", [response.status_code, response.body.message])
  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code in [200, 301, 302]
  count(response.body) > 0

  collaborators_list = concat(",\n", [response.body[i].login | response.body[i].type == "User"]) 
  msg := sprintf("%v outside collaborators have access to repository. \n The list of outside collaborators is: %v.", [count(response.body, collaborators_list)])
  sugg := sprintf("Adhere to the company policy by revoking the access of non-organization members for Github repo.")
  error := ""
}
