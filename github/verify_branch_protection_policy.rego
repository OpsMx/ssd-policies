package opsmx

default allow = false

request_components = [input.metadata.rest_url, "repos", input.metadata.github_org, input.metadata.github_repo,"branches",input.metadata.branch,"protection"]
request_url = concat("/",request_components)

token = input.metadata.github_access_token

request = {
    "method": "GET",
    "url": request_url,
    "headers": {
        "Authorization": sprintf("Bearer %v", [token]),
    },
}

response = http.send(request)
raw_body = response.raw_body
parsed_body = json.unmarshal(raw_body)
obj := response.body
has_key(x, k) {
   dont_care(x[k])
}
dont_care(_) = true
default branch_protection = false
branch_protection = has_key(obj, "required_pull_request_reviews")
allow {
  response.status_code = 200
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 404
  msg := ""
  sugg := "Kindly provide the accurate repository name, organization, and branch details"
  error := sprintf("%v %v",[response.status_code,response.body.message])
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 403
  msg := ""
  sugg := sprintf("The repository %v is private,Make this repository public to enable this feature", [input.metadata.github_repo])
  error := sprintf("%v %v",[response.status_code,response.body.message])
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 401
  msg := ""
  sugg := "Please provide the Appropriate Git Token for the User"
  error := sprintf("%s %v", [parsed_body.message,response.status])
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code = 500
  msg := "Internal Server Error"
  sugg := ""
  error := "GitHub is not reachable"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  branch_protection != true
  msg := sprintf("Github repo %v of branch %v is not protected", [input.metadata.github_repo, input.metadata.default_branch])
  sugg := sprintf("Adhere to the company policy by enforcing Code Owner Reviews for %s Github repo",[input.metadata.github_repo])
  error := ""
}
