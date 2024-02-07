package opsmx
import future.keywords.in

default allow = false

request_components = [input.metadata.ssd_secret.gitlab.rest_api_url,"api/v4/groups",input.metadata.ssd_secret.gitlab.group_id,"members"]

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

access = response.body

admins = {user |
    some i
    user = access[i];
    user.access_level == 50
}

admin_users = count(admins)

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  response.status_code == 401
  msg := ""
  error := "Unauthorized to check repository branch protection policy configuration due to Bad Credentials."
  sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 404
  msg := ""
  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository branch protection policy configuration."
  error := "Mentioned branch for Repository not found while trying to fetch repository branch protection policy configuration."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 500
  msg := "Internal Server Error."
  sugg := ""
  error := "Gitlab is not reachable."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  admin_users <= 1
  msg := sprintf("Group %v should have more than one owner so access to the code is not jeopardized",[input.metadata.ssd_secret.gitlab.group_id,])
  sugg := "To reduce the attack surface it is recommended to have more than 1 admin of an organization or group"
  error := ""
}
