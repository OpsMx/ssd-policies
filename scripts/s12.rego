package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

build_account = input.metadata.ssd_secret.jenkins.name

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": build_account}]{
	input.metadata.build_image_sha == "" 
	msg = ""
	sugg = "Ensure that build platform is integrated with SSD."
	error = "Complete Build Artifact information could not be identified."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": build_account}]{
	input.metadata.image_sha == ""
	msg = ""
	sugg = "Ensure that deployment platform is integrated with SSD using Admission Controller."
	error = "Artifact information could not be identified from Deployment Environment."
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": build_account}]{
	input.metadata.image_sha != input.metadata.build_image_sha
	not policy_name in exception_list
	msg = sprintf("Non-identical by hash artifacts identified at Build stage and Deployment Environment.\nBuild Image: %v:%v \n Deployed Image: %v:%v", [input.metadata.build_image, input.metadata.build_image_tag, input.metadata.image, input.metadata.image_tag])
	sugg = "Ensure that built image details & deployed Image details match. Check for possible misconfigurations."
	error = ""
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus, "accountName": build_account}]{
	input.metadata.image_sha != input.metadata.build_image_sha
	policy_name in exception_list
	msg = sprintf("Non-identical by hash artifacts identified at Build stage and Deployment Environment.\nBuild Image: %v:%v \n Deployed Image: %v:%v", [input.metadata.build_image, input.metadata.build_image_tag, input.metadata.image, input.metadata.image_tag])
	sugg = "Ensure that built image details & deployed Image details match. Check for possible misconfigurations."
	error = ""
	alertStatus := "exception"
}
