package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scm_account = input.metadata.ssd_secret.github.name

request_url = concat("/", [input.metadata.ssd_secret.github.url, "orgs", input.metadata.owner, "members?role=admin"])

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
	msg := ""
	error := "401 Unauthorized: Unauthorized to check organisation members."
	sugg := "Kindly check the access token. It must have enough permissions to get organisation members."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 404
	msg := ""
	sugg := "Kindly check if the repository provided is correct and the access token has rights to read organisation members. Also check if the repository belongs to an organization."
	error := "Mentioned branch for Repository not found while trying to fetch organisation members. Either Organisation/Repository name is incorrect or the repository does not belong to an organization."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	response.status_code == 500
	msg := "Internal Server Error."
	sugg := ""
	error := sprintf("500 Internal Server Error. Received Error while checking organisation members for %s.", [input.metadata.owner])
	alertStatus := "error"
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	codes = [401, 404, 500, 200, 301, 302]
	not response.status_code in codes
	msg := ""
	error := sprintf("Unable to fetch organisation members. Error %v:%v receieved from Github.", [response.status_code, response.body.message])
	sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	alertStatus := "error"
}

default denial_list = false

denial_list = matched_users

matched_users[user] {
	users := [response.body[i].login | response.body[i].type == "User"]
	user := users[_]
	patterns := ["r", "bot", "auto", "test", "jenkins", "drone", "github", "gitlab", "aws", "azure"]
	some pattern in patterns
		regex.match(pattern, user)
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}] {
	counter := count(denial_list)
	counter > 0
	not policy_name in exception_list
	denial_list_str := concat(", ", denial_list)
	msg := sprintf("Owner access of Github Organization is granted to bot users. Number of bot users having owner access: %v. Name of bots having owner access: %v", [counter, denial_list_str])
	sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v Organization.", [input.metadata.owner])
	error := ""
	alertStatus := "active"
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}] {
	counter := count(denial_list)
	counter > 0
	policy_name in exception_list
	denial_list_str := concat(", ", denial_list)
	msg := sprintf("Owner access of Github Organization is granted to bot users. Number of bot users having owner access: %v. Name of bots having owner access: %v", [counter, denial_list_str])
	sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v Organization.", [input.metadata.owner])
	error := ""
	alertStatus := "exception"
}
