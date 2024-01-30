package opsmx
import future.keywords.in

default allow = false
default number_of_merges = 0
default merges_unreviewed = []
default merges_reviewed_by_bots = []
default merges_reviewed_by_author = []

request_url = concat("", [input.metadata.ssd_secret.gitlab.rest_api_url,"api/v4/projects/", input.metadata.gitlab_project_id, "/merge_requests?state=merged&order_by=created_at"])

token = input.metadata.ssd_secret.gitlab.token

request = {
    "method": "GET",
    "url": request_url,
    "headers": {
        "PRIVATE-TOKEN": sprintf("%v", [token]),
    },
}

response = http.send(request)

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

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  codes = [401, 404, 500, 200, 302]
  not response.status_code in codes
  msg := ""
  error := sprintf("Error %v receieved from Gitlab upon trying to fetch Repository Configuration.", [response.body.message])
  sugg := "Kindly check Gitlab API is reachable and the provided access token has required permissions."
}

number_of_merges = count(response.bodu)
merges_unreviewed = [response.body[i].iid | count(response.body[i].reviewers) == 0]
merges_reviewed_by_bots = [response.body[i].iid | contains(response.body[i].reviewers[j].username, "bot")]
merges_reviewed_by_author = [response.body[i].iid | response.body[i].reviewers[j].username == response.body[i].author.username]

deny[{"alertMsg": msg, "error": error, "suggestion": sugg}]{
  count(merges_reviewed_by_bots) > 0
  msg := sprintf("Merge Request with bot user as reviewer found. Merge Request ID: %v.",[merges_reviewed_by_bots])
  sugg := "Adhere to security standards by restricting reviews by bot users."
  error := ""
}

deny[{"alertMsg": msg, "error": error, "suggestion": sugg}]{
  count(merges_reviewed_by_author) > 0
  msg := sprintf("Merge Request with Author as reviewer found. Merge Request ID: %v.",[merges_reviewed_by_author])
  sugg := "Adhere to security standards by restricting reviews by authors."
  error := ""
}

deny[{"alertMsg": msg, "error": error, "suggestion": sugg}]{
  count(merges_unreviewed) > 0
  msg := sprintf("Unreviewed Merge Requests found to be merged. Merge Request ID: %v.",[merges_unreviewed])
  sugg := "Adhere to security standards by restricting merges without reviews."
  error := ""
}
