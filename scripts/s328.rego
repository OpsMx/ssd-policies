package opsmx
import future.keywords.in

default allow = false

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scm_account = input.metadata.ssd_secret.github.name

request_components = [input.metadata.ssd_secret.github.url, "repos", input.metadata.owner, input.metadata.repository,"actions/permissions/workflow"] 

request_url = concat("/", request_components)

token = input.metadata.ssd_secret.github.token

request = {
	"method": "GET",
	"url": request_url,
	"headers": {
		"Authorization": sprintf("Bearer %v", [token])
	}
}

response = http.send(request)

allow {
response.status_code = 200
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 401
	msg := "Unauthorized to check repository configuration due to Bad Credentials."
	error := "401 Unauthorized."
	sugg := "Kindly check the access token. It must have enough permissions to get repository configurations."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 404
	msg := "Repository not found while trying to fetch Repository Configuration."
	sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository configuration."
	error := "Repo name or Organisation is incorrect."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 500
	msg := "Internal Server Error."
	sugg := ""
	error := "GitHub is not reachable."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.body.default_workflow_permissions == "write"
	not policy_name in exception_list
	msg := sprintf("Github actions workflow permissions are write permissions for %v/%v repository", [input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Adhere to the company policy by the Github actions workflow permission should be read for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}]{
	response.body.default_workflow_permissions == "write"
	policy_name in exception_list
	msg := sprintf("Github actions workflow permissions are write permissions for %v/%v repository", [input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Adhere to the company policy by the Github actions workflow permission should be read for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "exception"
}
