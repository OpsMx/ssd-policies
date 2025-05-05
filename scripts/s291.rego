package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scm_account = input.metadata.ssd_secret.gitlab.name

default allow = false

request_components = [input.metadata.ssd_secret.gitlab.url,"api/v4/user"]

request_url = concat("",request_components)

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
	error := "Unauthorized to check repository branch protection policy configuration due to Bad Credentials."
	sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 404
	msg := ""
	sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository branch protection policy configuration."
	error := "Mentioned branch for Repository not found while trying to fetch repository branch protection policy configuration."
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
	error := sprintf("Error %v receieved from Gitlab upon trying to fetch Repository Configuration.", [response.body.message])
	sugg := "Kindly check Gitlab API is reachable and the provided access token has required permissions."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.body.two_factor_enabled == false
	not policy_name in exception_list
	msg := sprintf("Gitlab Organisation %v doesnt have the mfa enabled.", [input.metadata.owner])
	sugg := sprintf("Adhere to the company policy by enabling 2FA for users of %s organisation.",[input.metadata.owner])
	error := ""
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}]{
	response.body.two_factor_enabled == false
	policy_name in exception_list
	msg := sprintf("Gitlab Organisation %v doesnt have the mfa enabled.", [input.metadata.owner])
	sugg := sprintf("Adhere to the company policy by enabling 2FA for users of %s organisation.",[input.metadata.owner])
	error := ""
	alertStatus := "exception"
}
