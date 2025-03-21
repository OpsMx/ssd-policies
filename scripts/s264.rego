	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default approved_servers = ""
	default list_approved_user_str = ""

	list_approved_user_str = input.metadata.ssd_secret.build_access_config.approved_user
	list_approved_users = split(list_approved_user_str, ",")
	approved_servers = input.metadata.ssd_secret.build_access_config.url
	build_url = split(input.metadata.build_url, "/")[2]
	build_user = input.metadata.build_user

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus }] {
		approved_servers == ""
		msg:=""
		sugg:="Set the BuildAccessConfig.Credentials parameter with trusted build server URLs and users to strengthen artifact validation during the deployment process."
		error:="The essential list of approved build URLs and users remains unspecified."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error,  "exception": "", "alertStatus": alertStatus }]{
		approved_servers != ""
		list_approved_user_str == ""
		msg := ""
		sugg := "Please set the list of authorised users in integrations configuration to strengthen artifact validation during the deployment process."
		error := "The essential list of approved build users remains unspecified."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus }]{
		approved_servers != ""
		not input.metadata.build_user in list_approved_users
		not policy_name in exception_list
		msg:=sprintf("The artifact build has not been created by an approved user.\nPlease verify the artifacts origin.\nBuild User: %v \nApproved Users: %v", [build_user, list_approved_user_str])
		sugg:="Ensure the artifact is sourced from an approved user."
		error:=""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus }]{
		approved_servers != ""
		not input.metadata.build_user in list_approved_users
		policy_name in exception_list
		msg:=sprintf("The artifact build has not been created by an approved user.\nPlease verify the artifacts origin.\nBuild User: %v \nApproved Users: %v", [build_user, list_approved_user_str])
		sugg:="Ensure the artifact is sourced from an approved user."
		error:=""
		alertStatus := "exception"
	}
