package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scm_account = input.metadata.ssd_secret.gitlab.name

default allow = false
default private_repo = ""

request_url = concat("", [input.metadata.ssd_secret.gitlab.url, "api/v4/projects/", input.metadata.gitlab_project_id])

token = input.metadata.ssd_secret.gitlab.token

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

deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 401
	msg := ""
	error := "Unauthorized to check repository configuration due to Bad Credentials."
	sugg := "Kindly check the access token. It must have enough permissions to get repository configurations."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 404
	msg := ""
	sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository configuration."
	error := "Repository not found while trying to fetch Repository Configuration."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 500
	msg := "Internal Server Error."
	sugg := ""
	error := "Gitlab is not reachable."
	alertStatus := "error"
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	codes = [401, 404, 500, 200, 302]
	not response.status_code in codes
	msg := ""
	error := sprintf("Error %v receieved from Github upon trying to fetch Repository Configuration.", [response.body.message])
	sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.body.visibility != "private"
	not policy_name in exception_list
	msg := sprintf("Gitlab Project %v is publically visible.", [input.metadata.repository])
	sugg := "Kindly adhere to security standards and change the visibility of the repository to private."
	error := ""
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}]{
	response.body.visibility != "private"
	policy_name in exception_list
	msg := sprintf("Gitlab Project %v is publically visible.", [input.metadata.repository])
	sugg := "Kindly adhere to security standards and change the visibility of the repository to private."
	error := ""
	alertStatus := "exception"
}
