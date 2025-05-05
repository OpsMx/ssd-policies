package opsmx

import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scm_account = input.metadata.ssd_secret.gitlab.name

request_url = concat("", [input.metadata.ssd_secret.gitlab.url,"api/v4/projects/", input.metadata.gitlab_project_id, "/members"])

token = input.metadata.ssd_secret.gitlab.token

request = {
	"method": "GET",
	"url": request_url,
	"headers": {
		"PRIVATE-TOKEN": sprintf("%v", [token]),
	},
}

response = http.send(request)

deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 401
	msg := ""
	error := "Unauthorized to check repository members due to Bad Credentials."
	sugg := "Kindly check the access token. It must have enough permissions to get repository members."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 404
	msg := ""
	sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository members."
	error := "Mentioned branch for Repository not found while trying to fetch repository members."
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

default denial_list = false

denial_list = matched_users

matched_users[user] {
	users := [response.body[i].username | response.body[i].access_level == 50]
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
	msg := sprintf("Owner access of Gitlab Repository is granted to bot users. \n Number of bot users having owner access: %v. \n Name of bots having owner access: %v", [counter, denial_list_str])
	sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v/%v Repository.", [input.metadata.repository,input.metadata.owner])
	error := ""
	alertStatus := "active"
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}] {
	counter := count(denial_list)
	counter > 0
	policy_name in exception_list
	denial_list_str := concat(", ", denial_list)
	msg := sprintf("Owner access of Gitlab Repository is granted to bot users. \n Number of bot users having owner access: %v. \n Name of bots having owner access: %v", [counter, denial_list_str])
	sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v/%v Repository.", [input.metadata.repository,input.metadata.owner])
	error := ""
	alertStatus := "exception"
}
