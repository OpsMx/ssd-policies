package opsmx
import future.keywords.in

default allow = false

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scm_account = input.metadata.ssd_secret.github.name

request_components = [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository,"dependency-graph/sbom"]
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

deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 401
	error := sprintf("Unauthorized to check repository configurations for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
	msg := ""
	sugg := "Kindly check the access token. It must have enough permissions to get repository configurations."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 404
	msg := "Repository SBOM not found while trying to fetch Repository Configuration."
	sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository configuration. Also, check if dependency mapping is enabled."
	error := ""
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 500
	msg := "Internal Server Error."
	sugg := ""
	error := sprintf("500 Internal Server Error. Received Error while checking repository configurations for %s/%s.", [input.metadata.owner, input.metadata.repository])
	alertStatus := "error"
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	codes = [401, 404, 500, 200, 301, 302]
	not response.status_code in codes
	msg := "Unable to fetch repository configuration."
	error := sprintf("Error %v:%v receieved from Github upon trying to fetch Repository Configuration.", [response.status_code, response.body.message])
	sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}] {
	response.body.sbom = "" 
	error := sprintf("The SBOM could not be fetched for repository %v/%v, hence Centralized package manager settings Policy cannot be validated.", [input.metadata.owner, input.metadata.repository])
	sugg := "Please make sure there are some packages in the GitHub Repository."
	msg := ""
	alertStatus := "error"
}

default_pkg_list = []
deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	pkg_list = [pkg.name | pkg := response.body.sbom.packages[_]
							pkg.name != response.body.sbom.name
							not startswith(pkg.name, "actions:")]

	count(pkg_list) == 0
	not policy_name in exception_list
	msg := sprintf("The GitHub repository %v/%v lacks the necessary configuration files for package managers.", [input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Adhere to the company policy and consider adding the necessary package manager configuration files to the GitHub repository %v/%v.", [input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}]{
	pkg_list = [pkg.name | pkg := response.body.sbom.packages[_]
							pkg.name != response.body.sbom.name
							not startswith(pkg.name, "actions:")]

	count(pkg_list) == 0
	policy_name in exception_list
	msg := sprintf("The GitHub repository %v/%v lacks the necessary configuration files for package managers.", [input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Adhere to the company policy and consider adding the necessary package manager configuration files to the GitHub repository %v/%v.", [input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "exception"
}
