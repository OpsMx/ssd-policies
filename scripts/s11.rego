package opsmx
import future.keywords.in

default allow = false

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scm_account = input.metadata.ssd_secret.github.name

request_components = [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository, "actions", "permissions", "workflow"]
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

deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 401
	msg := sprintf("Unauthorized to check Repository Workflow Permissions for organisation %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
	error := sprintf("401 Unauthorized. Unauthorized to check Workflow Permissions for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
	sugg := "Kindly check the access token. It must have enough permissions to get organisation workflow permissions."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 404
	error := "Mentioned Repository or workflows not found while trying to fetch repository workflow permissions."
	sugg := "Kindly check if the organisation provided is correct and the access token has rights to read organisation configuration. Also, verify if the repository belongs to an organisation. The two-factor authentication feature is not provided for individual repositories which are not owned by any oranisation."
	msg := ""
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 500
	msg := "Internal Server Error."
	sugg := ""
	error := sprintf("500 Internal Server Error. Received Error while checking repository workflow configuration for %s/%s.", [input.metadata.owner, input.metadata.repository])
	alertStatus := "error"
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	codes = [401, 404, 500, 200, 302]
	not response.status_code in codes
	msg := "Unable to fetch repository workflow permissions."
	error := sprintf("Error %v:%v receieved from Github upon trying to fetch repository workflow permissions.", [response.status_code, response.body.message])
	sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	alertStatus := "error"
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.body.default_workflow_permissions != "read"
	not policy_name in exception_list
	msg := sprintf("Default workflow permissions for Repository %v/%v is not set to read.", [input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Adhere to the company policy by enforcing default_workflow_permissions of Repository %v/%v to read only.", [input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "active"
}
deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}]{
	response.body.default_workflow_permissions != "read"
	policy_name in exception_list
	msg := sprintf("Default workflow permissions for Repository %v/%v is not set to read.", [input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Adhere to the company policy by enforcing default_workflow_permissions of Repository %v/%v to read only.", [input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "exception"
}
