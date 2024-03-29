package opsmx
import future.keywords.in

default allow = false

request_components = [input.metadata.ssd_secret.bitbucket.rest_api_url,"2.0/workspaces", input.metadata.owner, "permissions"]

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
  msg := ""
  error := "401 Unauthorized: Unauthorized to check organisation members."
  sugg := "Kindly check the access token. It must have enough permissions to get organisation members."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 404
  msg := ""
  sugg := "Kindly check if the repository provided is correct and the access token has rights to read organisation members."
  error := "Mentioned branch for Repository not found while trying to fetch organisation members. Repo name or Organisation is incorrect."
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
  error := sprintf("Unable to fetch organisation members. Error %v:%v receieved from Github.", [response.status_code, response.body.message])
  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
}

admins = [response.body.values[i].user.display_name | response.body.values[i].permission == "owner"]

default denial_list = false

denial_list = matched_users

matched_users[user] {
    users := admins
    user := users[_]
    patterns := ["bot", "auto", "test", "jenkins", "drone", "github", "gitlab", "aws", "azure"]
    some pattern in patterns
        regex.match(pattern, user)
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}] {
  counter := count(denial_list)
  counter > 0
  denial_list_str := concat(", ", denial_list)
  msg := sprintf("Owner access of Github Organization is granted to bot users. Number of bot users having owner access: %v. Name of bots having owner access: %v", [counter, denial_list_str])
  sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v Organization.", [input.metadata.owner])
  error := ""
}
