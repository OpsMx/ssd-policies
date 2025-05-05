package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scm_account = input.metadata.ssd_secret.github.name

token = input.metadata.ssd_secret.github.token
request_components = [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository, "activity?time_period=quarter&activity_type=push&per_page=500"]

collaborators_components = [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository, "collaborators"]
collaborators_url = concat("/",collaborators_components)

collaborators = {
	"method": "GET",
	"url": collaborators_url,
	"headers": {
		"Authorization": sprintf("Bearer %v", [token]),
	},
}

coll_resp = http.send(collaborators)

responsesplit = coll_resp.body

coll_users = {coluser |
	some i
	coluser = responsesplit[i];
	coluser.role_name != "admin"
	coluser.type == "User"
}

request_url = concat("/",request_components)

request = {
	"method": "GET",
	"url": request_url,
	"headers": {
		"Authorization": sprintf("Bearer %v", [token]),
	},
}
resp = http.send(request)
link_1 = split(resp.headers.link[0], " ")[0]
decoded_link_1 = replace(link_1, "\u003e;", "")
decoded_link_2 = replace(decoded_link_1, "\u003c", "")
link_request = {
	"method": "GET",
	"url": decoded_link_2,
	"headers": {
		"Authorization": sprintf("Bearer %v", [token]),
	},
}
resp2 =  http.send(link_request)

evnt_users = resp.body

evnt_logins = {user |
	some i
	user = evnt_users[i];
	user.actor.type == "User"
}

login_values[login] {
	user = evnt_logins[_]
	login = user.actor.login
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	allusers = coll_users[_]
	eventlogins = evnt_logins[_]
	allusers.login == login_values[_]
	not policy_name in exception_list
	msg := sprintf("Access of Github repository %s has been granted to users %v who have no activity from last three months", [input.metadata.github_repo,login_values[_]])
	sugg := "Adhere to the company policy and revoke access of inactive members"
	error := ""
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}]{
	allusers = coll_users[_]
	eventlogins = evnt_logins[_]
	allusers.login == login_values[_]
	policy_name in exception_list
	msg := sprintf("Access of Github repository %s has been granted to users %v who have no activity from last three months", [input.metadata.github_repo,login_values[_]])
	sugg := "Adhere to the company policy and revoke access of inactive members"
	error := ""
	alertStatus := "exception"
}
