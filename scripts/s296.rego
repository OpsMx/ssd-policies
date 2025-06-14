package opsmx
import future.keywords.in

default allow = false
default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scm_account = input.metadata.ssd_secret.bitbucket.name

request_components = [input.metadata.ssd_secret.bitbucket.url,"2.0/repositories", input.metadata.owner, "policies/branch-restrictions"]

request_url = concat("/",request_components)

headers = {
	"Authorization": auth_header
}

auth_header = sprintf("Basic %s", [base64_encode(concat(":",[username,password]))]) {
	input.metadata.ssd_secret.bitbucket.isBasicAuth
	username = input.metadata.ssd_secret.bitbucket.user
	password = input.metadata.ssd_secret.bitbucket.password
}

auth_header = sprintf("Bearer %s", [input.metadata.ssd_secret.bitbucket.token]) {
	not input.metadata.ssd_secret.bitbucket.isBasicAuth
}


# Helper function to base64 encode a string
base64_encode(s) = encoded {
		encoded = base64.encode(s)
}

request = {
	"method": "GET",
	"url": request_url,
	"headers": headers,
}

response = http.send(request)

allow {
response.status_code = 200
}

abc = [user |
	user = response.body.values[i];
	user.kind == "require_approvals_to_merge"
	user.pattern = input.metadata.branch 
]

reviewers = abc[_].value

deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 401
	msg := "Unauthorized to check repository branch protection policy configuration due to Bad Credentials."
	error := "401 Unauthorized."
	sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 404
	msg := "Mentioned branch for Repository not found while trying to fetch repository branch protection policy configuration."
	sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository branch protection policy configuration."
	error := "Repo name or Organisation is incorrect."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 500
	msg := "Internal Server Error."
	sugg := ""
	error := "Bitbucket is not reachable."
	alertStatus := "error"
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	codes = [401, 404, 500, 200, 301, 302]
	not response.status_code in codes
	msg := "Unable to fetch repository branch protection policy configuration."
	error := sprintf("Error %v:%v receieved from Bitbucket upon trying to fetch repository branch protection policy configuration.", [response.status_code, response.body.message])
	sugg := "Kindly check Bitbucket API is reachable and the provided access token has required permissions."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	abc[_].value <= 1
	not policy_name in exception_list
	msg := sprintf("The branch protection policy that mandates a pull request before merging has mandatory reviewers count less than required for the %s branch of the Bitbucket", [input.metadata.branch])
	sugg := "Adhere to the company policy by establishing the correct minimum reviewers for Bitbucket"
	error := ""
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}]{
	abc[_].value <= 1
	policy_name in exception_list
	msg := sprintf("The branch protection policy that mandates a pull request before merging has mandatory reviewers count less than required for the %s branch of the Bitbucket", [input.metadata.branch])
	sugg := "Adhere to the company policy by establishing the correct minimum reviewers for Bitbucket"
	error := ""
	alertStatus := "exception"
}
