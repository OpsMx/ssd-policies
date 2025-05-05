package opsmx
import future.keywords.in

default allow = false

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scm_account = input.metadata.ssd_secret.github.name

request_components = [input.metadata.ssd_secret.github.url, "repos", input.metadata.owner, input.metadata.repository, "branches", input.metadata.branch, "protection"]
request_url = concat("/", request_components)

token = input.metadata.ssd_secret.github.token

request = {
	"method": "GET",
	"url": request_url,
	"headers": {
		"Authorization": sprintf("Bearer %v", [token]),
	},
}

response = http.send(request)


deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 404
	error := sprintf("The branch protection policy for %s branch for Repository %s/%s not found while trying to fetch repository branch protection policy configuration.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	sugg := "Kindly check if the repository provided is correct and the branch protection policy is configured."
	msg := ""
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 401
	error := sprintf("Unauthorized to check repository branch protection policy configuration for branch %s of repository %s/%s due to Bad Credentials.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	msg := ""
	sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 500
	msg := "Internal Server Error."
	sugg := ""
	error := sprintf("500 Internal Server Error. Received Error while checking repository branch configuration for %s/%s.", [input.metadata.owner, input.metadata.repository])
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	not response.status_code in [401, 404, 500, 200, 301, 302]
	msg := ""
	error := sprintf("Error %v:%v receieved from Github upon trying to fetch repository branch protection policy configuration for %v/%v.", [response.status_code, response.body.message, input.metadata.owner, input.metadata.repository])
	sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}]{
	response.body.allow_deletions.enabled == true
	policy_name in exception_list
	msg := sprintf("Deletion of Branch is not restricted for Branch %v of Github Repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Restrict Branch Deletion operations by enforcing required branch protection policies on branch %v of Github repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "exception"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.body.allow_deletions.enabled == true
	not policy_name in exception_list
	msg := sprintf("Deletion of Branch is not restricted for Branch %v of Github Repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Restrict Branch Deletion operations by enforcing required branch protection policies on branch %v of Github repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "active"
}
