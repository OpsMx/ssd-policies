package opsmx
import future.keywords.in

default allow = false

request_components = [input.metadata.ssd_secret.bitbucket.rest_api_url,"2.0/workspaces", input.metadata.owner, "permissions/repositories",input.metadata.repository]

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

#admin = [response.body.values[i] | response.body.values[i].type == "repository_permission" | response.body.values[i].permission == "admin"]

admin = [user |
    user = response.body.values[i];
    user.type == "repository_permission"
    user.permission == "admin"
]

admin_users = count(admin)

all = [user |
    user = response.body.values[i];
    user.type == "repository_permission"
    user.user.type == "user"
]

total_users = count(all)

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
  error := "Bitbucket is not reachable."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  admin_percentage = admin_users / total_users * 100

  admin_percentage > 5
  msg := sprintf("More than 5 percentage of total collaborators of %v Bitbucket repository have admin access", [input.metadata.repository])
  sugg := sprintf("Adhere to the company policy and revoke admin access to some users of the repo %v", [input.metadata.repository])
  error := ""
}
sai
