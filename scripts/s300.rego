package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scm_account = input.metadata.ssd_secret.bitbucket.name

request_components = [input.metadata.ssd_secret.bitbucket.url,"2.0/workspaces", input.metadata.owner, "permissions/repositories", input.metadata.repository]
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

admins = [response.body.values[i].user.display_name| response.body.values[i].permission == "admin"]

response = http.send(request)

deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 401
	msg := sprintf("Unauthorized to check collaborators for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
	error := sprintf("401 Unauthorized. Unauthorized to check repository collaborators for repository %s/%s due to Bad Credentials.", [input.metadata.owner, input.metadata.repository])
	sugg := "Kindly check the access token. It must have enough permissions to get repository collaborators."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 404
	msg := sprintf("Repository %s/%s not found while trying to fetch Repository collaborators.", [input.metadata.owner, input.metadata.repository])
	sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository collaborators."
	error := sprintf("Repository %s/%s not found while trying to fetch Repository collaborators.", [input.metadata.owner, input.metadata.repository])
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
	response.status_code == 500
	msg := "Internal Server Error."
	sugg := ""
	error := sprintf("500 Internal Server Error. Received Error while checking collaborators for repository %s/%s.", [input.metadata.owner, input.metadata.repository])
	alertStatus := "error"
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	codes = [401, 404, 500, 200, 301, 302]
	not response.status_code in codes
	msg := "Unable to fetch repository collaborators."
	error := sprintf("Error %v:%v receieved from Bitbucket upon trying to fetch repository collaborators.", [response.status_code, response.body.message])
	sugg := "Kindly check Bitbucket API is reachable and the provided access token has required permissions."
	alertStatus := "error"
}

default denial_list = false

denial_list = matched_users

matched_users[user] {
	users := admins
	user := users[_]
	patterns := ["bot", "auto", "test", "jenkins", "drone", "github", "gitlab", "aws", "azure"]
	some pattern in patterns
		regex.match(pattern, user)
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}] {
	counter := count(denial_list)
	counter > 0
	not policy_name in exception_list
	denial_list_str := concat(", ", denial_list)
	msg := sprintf("Admin access of Bitbucket Repository providing ability to merge code is granted to bot users. Number of bot users having permissions as repository admins: %v. Name of bots having permissions as repository admins: %v", [counter, denial_list_str])
	sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v/%v Repository.", [input.metadata.repository,input.metadata.owner])
	error := ""
	alertStatus := "active"
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}] {
	counter := count(denial_list)
	counter > 0
	policy_name in exception_list
	denial_list_str := concat(", ", denial_list)
	msg := sprintf("Admin access of Bitbucket Repository providing ability to merge code is granted to bot users. Number of bot users having permissions as repository admins: %v. Name of bots having permissions as repository admins: %v", [counter, denial_list_str])
	sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v/%v Repository.", [input.metadata.repository,input.metadata.owner])
	error := ""
	alertStatus := "exception"
}
