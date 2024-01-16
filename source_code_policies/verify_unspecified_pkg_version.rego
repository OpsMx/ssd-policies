package opsmx
import future.keywords.in

default allow = false

request_components = [input.metadata.ssd_secret.github.rest_api_url,"repos", input.metadata.owner, input.metadata.repository,"dependency-graph/sbom"]
request_url = concat("/",request_components)

token = input.metadata.ssd_secret.github.token

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
  msg := "Unauthorized to check repository configuration due to Bad Credentials."
  error := "401 Unauthorized."
  sugg := "Kindly check the access token. It must have enough permissions to get repository configurations."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 404
  msg := "Repository not found while trying to fetch Repository Configuration."
  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository configuration."
  error := "Repo name or Organisation is incorrect."
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
  msg := "Unable to fetch repository configuration."
  error := sprintf("Error %v:%v receieved from Github upon trying to fetch Repository Configuration.", [response.status_code, response.body.message])
  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}] {
    response.body.sbom = "" 
    error := sprintf("The SBOM could not be fetched, hence Centralized package manager settings Policy cannot be validated.", [input.metadata.repository])
    sugg := "Please make sure there are some packages in the GitHub Repository."
    msg := ""
}

default pkg_without_version = []

pkg_without_version = [pkg2.name | pkg2 := response.body.sbom.packages[_]
                            pkg.name != response.body.sbom.name
                            not startswith(pkg2.name, "actions:")
                            pkg2.versionInfo == ""]

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
    count(pkg_without_version) != 0
    msg := sprintf("The GitHub repository %v/%v exhibits packages with inadequate versioning.", [input.metadata.owner, input.metadata.repository])
    sugg := sprintf("Adhere to the company policy and mandate proper tagging and versioning for packages of %v/%v repository.", [input.metadata.owner, input.metadata.repository])
    error := ""
}
