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

check_protect = response.body.values

branch_protect = {user |
    some i
    user = check_protect[i];
    user.type == "branchrestriction"
    user.pattern = input.metadata.branch 
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  response.status_code == 401
  msg := "Unauthorized to check repository branch protection policy configuration due to Bad Credentials."
  error := "401 Unauthorized."
  sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 404
  msg := "Mentioned branch for Repository not found while trying to fetch repository branch protection policy configuration."
  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository branch protection policy configuration."
  error := "Repo name or Organisation is incorrect."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 500
  msg := "Internal Server Error."
  sugg := ""
  error := "Bitbucket is not reachable."
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  codes = [401, 404, 500, 200, 301, 302]
  not response.status_code in codes
  msg := "Unable to fetch repository branch protection policy configuration."
  error := sprintf("Error %v:%v receieved from Bitbucket upon trying to fetch repository branch protection policy configuration.", [response.status_code, response.body.message])
  sugg := "Kindly check Bitbucket API is reachable and the provided access token has required permissions."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code in [200]
  count(branch_protect) == 0
  msg := sprintf("Branch %v of Bitbucket repository %v is not protected by a branch protection policy.", [input.metadata.branch, input.metadata.repository])
  sugg := sprintf("Adhere to the company policy by enforcing Branch Protection Policy for branches of %v Bitbucket repository.",[input.metadata.repository])
  error := ""
}
