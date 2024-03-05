package opsmx
import future.keywords.in

default allow = false

request_components = [input.metadata.ssd_secret.bitbucket.rest_api_url,"2.0/repositories", input.metadata.owner, input.metadata.repository, "branch-restrictions"]

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

admins= [response.body.values[i].users[_].display_name | response.body.values[i].kind == "restrict_merges"]

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  response.status_code == 401
  msg := "Unauthorized to check organisation configuration due to Bad Credentials."
  error := "401 Unauthorized."
  sugg := "Kindly check the access token. It must have enough permissions to get organisation configurations."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 404
  msg := "Mentioned Organisation not found while trying to fetch org configuration."
  sugg := "Kindly check if the organisation provided is correct and the access token has rights to read organisation configuration."
  error := "Organisation name is incorrect."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 500
  msg := "Internal Server Error."
  sugg := ""
  error := "Bitbucket is not reachable."
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  codes = [401, 404, 500, 200, 302]
  not response.status_code in codes
  msg := "Unable to fetch organisation configuration."
  error := sprintf("Error %v:%v receieved from Bitbucket upon trying to fetch organisation configuration.", [response.status_code, response.body.message])
  sugg := "Kindly check Bitbucket API is reachable and the provided access token has required permissions."
}

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
  msg := sprintf("Maintainer and Admin access of Bitbucket Repository providing ability to merge code is granted to bot users. Number of bot users having permissions to merge: %v. Name of bots having permissions to merge: %v", [counter, denial_list_str])
  sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v/%v Repository.", [input.metadata.repository,input.metadata.owner])
  error := ""
}
