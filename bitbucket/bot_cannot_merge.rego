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

check = response.body

ab = check.values

abc = {user |
    some i
    user = ab[i];
    user.kind == "restrict_merges"
}

bot_users = {"bot", "auto", "test", "jenkins", "drone", "github", "gitlab", "aws", "azure"}

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

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  checkbot = abc[_].users
  checkbot[_].display_name == bot_users[checkbot[_].display_name]
  msg = sprintf("Bitbucket users cannot merge the code %v", [checkbot[_].display_name])
  sugg := "Adhere to the company policy and revoke admin access of bot user"
  error := ""
}
