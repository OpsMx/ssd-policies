package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scm_account = input.metadata.ssd_secret.scmCreds.name

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scm_account}]{
	input.metadata.parent_repo != ""
	parent_repo_owner = split(input.metadata.parent_repo, "/")[0]
	parent_repo_owner != input.metadata.owner
	not policy_category in exception_list
	msg := sprintf("The pipeline uses a forked repo from a different organization %s from %s.", [input.metadata.parent_repo, input.metadata.owner])
	sugg := "Refrain from running pipelines originating from forked repos not belonging to the same organization."
	error := ""
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": scm_account}]{
	input.metadata.parent_repo != ""
	parent_repo_owner = split(input.metadata.parent_repo, "/")[0]
	parent_repo_owner != input.metadata.owner
	policy_category in exception_list
	msg := sprintf("The pipeline uses a forked repo from a different organization %s from %s.", [input.metadata.parent_repo, input.metadata.owner])
	sugg := "Refrain from running pipelines originating from forked repos not belonging to the same organization."
	error := ""
	alertStatus := "exception"
}
