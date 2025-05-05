package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

artifact_account = input.metadata.ssd_secret.imageCreds.name

default approved_artifact_repos = []
default image_source = ""

image_details = split(input.metadata.image,"/")

image_source = concat("/",["docker.io", image_details[0]]) {
	count(image_details) <= 2
	not contains(image_details[0], ".")
}

image_source = concat("/",[image_details[0], image_details[1]]) {
	count(image_details) == 2
	contains(image_details[0], ".")
}

image_source = concat("/",[image_details[0], image_details[1]]) {
	count(image_details) == 3
}

approved_artifact_repos = split(input.metadata.ssd_secret.imageCreds.repo, ",")
decision:= image_source in approved_artifact_repos
deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": artifact_account}]{
	count(approved_artifact_repos) == 0
	error := "The essential list of Authorized Artifact Repositories remains unspecified."
	sugg := "Set the AuthorizedArtifactRepos parameter with trusted Artifact Repo to strengthen artifact validation during the deployment process."
	msg := ""
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": artifact_account}]{
	not image_source in approved_artifact_repos
	not policy_name in exception_list
	msg := sprintf("The artifact %v:%v has not been sourced from an authorized artifact repo.\nPlease verify the artifacts origin against the following Authorized Artifact Repositories: %v", [input.metadata.image, input.metadata.image_tag, input.metadata.ssd_secret.imageCreds.repo])
	sugg := "Ensure the artifact is sourced from an authorized artifact repo."
	error := ""
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": artifact_account}]{
	not image_source in approved_artifact_repos
	policy_name in exception_list
	msg := sprintf("The artifact %v:%v has not been sourced from an authorized artifact repo.\nPlease verify the artifacts origin against the following Authorized Artifact Repositories: %v", [input.metadata.image, input.metadata.image_tag, input.metadata.ssd_secret.imageCreds.repo])
	sugg := "Ensure the artifact is sourced from an authorized artifact repo."
	error := ""
	alertStatus := "exception"
}
