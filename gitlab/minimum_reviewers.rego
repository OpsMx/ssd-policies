package opsmx
import future.keywords.in

default allow = false

request_components = [input.metadata.ssd_secret.gitlab.rest_api_url,"api/v4/projects", input.metadata.project_id, "merge_requests"]

request_url = concat("/",request_components)

token = input.metadata.token

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
  codes = [401, 404, 500, 200, 301, 302]
  response.status_code in codes
  msg := "Unable to fetch repository configuration."
  error := sprintf("Error %v receieved from Gitlab upon trying to fetch Repository Configuration.", [response.body.message])
  sugg := "Kindly check Gitlab API is reachable and the provided access token has required permissions."
}


deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  #count(response.body[_].reviewers) == 0
  response.body[_].reviewers == []
  msg := sprintf("The branch protection policy that mandates a pull request before merging has mandatory reviewers count less than required for the %s branch of the %v on Gitlab", [input.metadata.branch,input.metadata.repository])
  sugg := sprintf("Adhere to the company policy by establishing the correct minimum reviewers for %s Gitlab repo", [input.metadata.repository])
  error := ""
}
