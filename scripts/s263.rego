package opsmx
import future.keywords.in 

default allow = false

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scm_account = input.metadata.ssd_secret.github.name

repo_search = [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository]
repo_searchurl = concat("/",repo_search)

branch_search = [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository,"branches",input.metadata.branch]
branch_searchurl = concat("/",branch_search)

protect_components = [input.metadata.ssd_secret.github.url,"repos", input.metadata.owner, input.metadata.repository,"branches",input.metadata.branch,"protection"]
protect_url = concat("/",protect_components)

token = input.metadata.ssd_secret.github.token

repo_search_request = {
	"method": "GET",
	"url": repo_searchurl,
	"headers": {
		"Authorization": sprintf("Bearer %v", [token]),
	},
}

branch_search_request = {
	"method": "GET",
	"url": branch_searchurl,
	"headers": {
		"Authorization": sprintf("Bearer %v", [token]),
	},
}

protect_search_request = {
	"method": "GET",
	"url": protect_url,
	"headers": {
		"Authorization": sprintf("Bearer %v", [token]),
	},
}

response = http.send(repo_search_request)

branch_response = http.send(branch_search_request)

branch_protect = http.send(protect_search_request)

branch_check = response.body.branch

AllowAutoMerge = response.body.allow_auto_merge

delete_branch_on_merge = response.body.delete_branch_on_merge

branch_protected = branch_response.body.protected

RequiredReviewers = branch_protect.body.required_pull_request_reviews.required_approving_review_count

AllowForcePushes = branch_protect.body.allow_force_pushes.enabled

AllowDeletions = branch_response.body.allow_deletions.enabled

RequiredSignatures = branch_protect.body.required_signatures.enabled

EnforceAdmins = branch_protect.body.enforce_admins.enabled

RequiredStatusCheck = branch_protect.body.required_status_checks.strict


deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	AllowAutoMerge == true
	not policy_name in exception_list
	msg := sprintf("The Auto Merge is enabled for the %s branch of %s/%s repository.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Please disable the Auto Merge for the %s branch of %s/%s repository.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}]{
	AllowAutoMerge == true
	policy_name in exception_list
	msg := sprintf("The Auto Merge is enabled for the %s branch of %s/%s repository.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Please disable the Auto Merge for the %s branch of %s/%s repository.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "exception"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	delete_branch_on_merge == true
	not policy_name in exception_list
	msg := "The branch protection policy that allows branch deletion is enabled."
	sugg := sprintf("Please disable the branch deletion of branch %s of repository %s/%s.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}]{
	delete_branch_on_merge == true
	policy_name in exception_list
	msg := "The branch protection policy that allows branch deletion is enabled."
	sugg := sprintf("Please disable the branch deletion of branch %s of repository %s/%s.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "exception"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	branch_protected == false
	not policy_name in exception_list
	msg := sprintf("Branch %v of Github repository %v/%v is not protected.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Make sure branch %v of %v/%v repo has some branch protection policies.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}]{
	branch_protected == false
	policy_name in exception_list
	msg := sprintf("Branch %v of Github repository %v/%v is not protected.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Make sure branch %v of %v/%v repo has some branch protection policies.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "exception"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	RequiredReviewers == 0
	not policy_name in exception_list
	msg := sprintf("The branch protection policy that mandates the minimum review for code merge requests has been deactivated for Branch %v of Github repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Activate branch protection: pull request and minimum 1 approval before merging for branch %s of %s/%s repository.",[input.metadata.branch, input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}]{
	RequiredReviewers == 0
	policy_name in exception_list
	msg := sprintf("The branch protection policy that mandates the minimum review for code merge requests has been deactivated for Branch %v of Github repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Activate branch protection: pull request and minimum 1 approval before merging for branch %s of %s/%s repository.",[input.metadata.branch, input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "exception"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	AllowForcePushes == true
	not policy_name in exception_list
	msg := sprintf("The branch protection policy that allows force pushes is enabled for Branch %v of Github repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Disable force push for branch %v of repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}]{
	AllowForcePushes == true
	policy_name in exception_list
	msg := sprintf("The branch protection policy that allows force pushes is enabled for Branch %v of Github repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Disable force push for branch %v of repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "exception"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	AllowDeletions == true
	not policy_name in exception_list
	msg := sprintf("The branch protection policy that allows branch deletion is enabled for Branch %v of Github repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Please disable the branch deletion of branch %v of repository %v/%v.",[input.metadata.branch, input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}]{
	AllowDeletions == true
	policy_name in exception_list
	msg := sprintf("The branch protection policy that allows branch deletion is enabled for Branch %v of Github repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Please disable the branch deletion of branch %v of repository %v/%v.",[input.metadata.branch, input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "exception"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	RequiredSignatures == true
	not policy_name in exception_list
	msg := sprintf("The branch protection policy that requires signature association with commits is disabled for Branch %v of Github repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Please activate the mandatory GitHub signature policy for branch %v of %v/%v repositoty.",[input.metadata.branch, input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}]{
	RequiredSignatures == true
	policy_name in exception_list
	msg := sprintf("The branch protection policy that requires signature association with commits is disabled for Branch %v of Github repository %v/%v.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Please activate the mandatory GitHub signature policy for branch %v of %v/%v repositoty.",[input.metadata.branch, input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "exception"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	EnforceAdmins == true
	not policy_name in exception_list
	msg := sprintf("The branch protection policy that enforces status checks for repository administrators is disabled for repository %v/%v.", [input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Please activate the branch protection policy, dont by pass status checks for repository administrators of branch %s of %s/%s repository.",[input.metadata.branch, input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}]{
	EnforceAdmins == true
	policy_name in exception_list
	msg := sprintf("The branch protection policy that enforces status checks for repository administrators is disabled for repository %v/%v.", [input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Please activate the branch protection policy, dont by pass status checks for repository administrators of branch %s of %s/%s repository.",[input.metadata.branch, input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "exception"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	RequiredStatusCheck == true
	not policy_name in exception_list
	msg := sprintf("The branch protection policy that requires status check is disabled for the repository %s/%s.", [input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Please activate the branch protection policy, requiring a need to be up-to-date with the base branch before merging for branch %s of %s/%s repo",[input.metadata.branch, input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}]{
	RequiredStatusCheck == true
	policy_name in exception_list
	msg := sprintf("The branch protection policy that requires status check is disabled for the repository %s/%s.", [input.metadata.owner, input.metadata.repository])
	sugg := sprintf("Please activate the branch protection policy, requiring a need to be up-to-date with the base branch before merging for branch %s of %s/%s repo",[input.metadata.branch, input.metadata.owner, input.metadata.repository])
	error := ""
	alertStatus := "exception"
}
