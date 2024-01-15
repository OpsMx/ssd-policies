package opsmx
import future.keywords.in

default allow = false

maintainers_url = concat("/", [input.metadata.ssd_secret.github.rest_api_url, "repos", input.metadata.owner, input.metadata.repository, "collaborators?permission=maintain&per_page=100"])
admins_url = concat("/", [input.metadata.ssd_secret.github.rest_api_url, "repos", input.metadata.owner, input.metadata.repository, "collaborators?permission=admin&per_page=100"])

maintainers_request = {
    "method": "GET",
    "url": maintainers_url,
    "headers": {
        "Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.github.token]),
    },
}

default maintainers_response = ""
maintainers_response = http.send(maintainers_request)
maintainers = [maintainers_response.body[i].login | maintainers_response.body[i].type == "User"]

admins_request = {
    "method": "GET",
    "url": admins_url,
    "headers": {
        "Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.github.token]),
    },
}

default admins_response = ""
admins_response = http.send(admins_request)

admins = [admins_response.body[i].login | admins_response.body[i].type == "User"]
non_admin_maintainers = [maintainers[idx] | not maintainers[idx] in admins]
complete_list = array.concat(admins, non_admin_maintainers)

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  maintainers_response.status_code == 401
  msg := ""
  error := "401 Unauthorized: Unauthorized to check repository collaborators."
  sugg := "Kindly check the access token. It must have enough permissions to get repository collaborators."
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  admins_response.status_code == 401
  msg := ""
  error := "401 Unauthorized: Unauthorized to check repository collaborators."
  sugg := "Kindly check the access token. It must have enough permissions to get repository collaborators."
}


deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  maintainers_response.status_code == 404
  msg := ""
  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository collaborators."
  error := "Mentioned branch for Repository not found while trying to fetch repository collaborators. Repo name or Organisation is incorrect."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  admins_response.status_code == 404
  msg := ""
  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository collaborators."
  error := "Mentioned branch for Repository not found while trying to fetch repository collaborators. Repo name or Organisation is incorrect."
}


deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  admins_response.status_code == 500
  msg := "Internal Server Error."
  sugg := ""
  error := "GitHub is not reachable."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  maintainers_response.status_code == 500
  msg := "Internal Server Error."
  sugg := ""
  error := "GitHub is not reachable."
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  codes = [401, 404, 500, 200, 301, 302]
  not admins_response.status_code in codes
  msg := ""
  error := sprintf("Unable to fetch repository collaborators. Error %v:%v receieved from Github.", [admins_response.status_code, admins_response.body.message])
  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  codes = [401, 404, 500, 200, 301, 302]
  not maintainers_response.status_code in codes
  msg := ""
  error := sprintf("Unable to fetch repository collaborators. Error %v:%v receieved from Github.", [maintainers_response.status_code, maintainers_response.body.message])
  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
}

default denial_list = false

denial_list = matched_users

matched_users[user] {
    users := complete_list
    user := users[_]
    patterns := ["bot", "auto", "test", "jenkins", "drone", "github", "gitlab", "aws", "azure"]
    some pattern in patterns
        regex.match(pattern, user)
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}] {
  counter := count(denial_list)
  counter > 0
  denial_list_str := concat(", ", denial_list)
  msg := sprintf("Maintainer and Admin access of Github Repository providing ability to merge code is granted to bot users. Number of bot users having permissions to merge: %v. Name of bots having permissions to merge: %v", [counter, denial_list_str])
  sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v/%v Repository.", [input.metadata.repository,input.metadata.owner])
  error := ""
}
