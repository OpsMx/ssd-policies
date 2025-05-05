package opsmx
import future.keywords.in

default allow = false

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scm_account = input.metadata.ssd_secret.github.name

request_components = [input.metadata.ssd_secret.github.url, "orgs", input.metadata.owner]
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

mfa_enabled = response.body.two_factor_requirement_enabled



deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 401
	error := "Unauthorized to check organisation configuration due to Bad Credentials."
	msg := ""
	sugg := "Kindly check the access token. It must have enough permissions to get organisation configurations."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 404
	error := "Mentioned Organisation not found while trying to fetch organisation configuration. The repository does not belong to an organisation."
	sugg := "Kindly check if the organisation provided is correct and the access token has rights to read organisation configuration. Also, verify if the repository belongs to an organisation. The two-factor authentication feature is not provided for individual repositories which are not owned by any oranisation."
	msg := ""
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 500
	msg := "Internal Server Error."
	sugg := ""
	error := sprintf("500 Internal Server Error. Received Error while checking organisation configuration for %s.", [input.metadata.owner])
	alertStatus := "error"
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	codes = [401, 404, 500, 200, 302]
	not response.status_code in codes
	msg := ""
	error := sprintf("Error %v:%v receieved from Github upon trying to fetch organisation configuration.", [response.status_code, response.body.message])
	sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}]{
	mfa_enabled == null
	policy_name in exception_list
	msg := sprintf("Github Organisation %v doesnt have the mfa enabled.", [input.metadata.owner])
	sugg := sprintf("Adhere to the company policy by enabling 2FA for %s organisation.",[input.metadata.owner])
	error := ""
	alertStatus := "exception"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	mfa_enabled == null
	not policy_name in exception_list
	msg := sprintf("Github Organisation %v does not have the mfa enabled.", [input.metadata.owner])
	sugg := sprintf("Adhere to the company policy by enabling 2FA for %s organisation.",[input.metadata.owner])
	error := ""
	alertStatus := "active"
}
