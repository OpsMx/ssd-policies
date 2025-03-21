	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	approved_server = split(input.metadata.ssd_secret.build_access_config.url, "/")[2]
	build_url = split(input.metadata.build_url, "/")[2]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}] {
		approved_server == ""
		msg:=""
		sugg:="Set the BuildAccessConfig.Credentials parameter with trusted build server URLs to strengthen artifact validation during the deployment process."
		error:="The essential list of approved build URLs remains unspecified"
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		approved_server != ""
		build_url != approved_server
		not policy_name in exception_list

		msg:=sprintf("The artifact has not been sourced from an approved build server.\nPlease verify the artifacts origin against the following approved build URLs: %v", [approved_server])
		sugg:="Ensure the artifact is sourced from an approved build server."
		error:=""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		approved_server != ""
		build_url != approved_server
		policy_name in exception_list
		
		msg:=sprintf("The artifact has not been sourced from an approved build server.\nPlease verify the artifacts origin against the following approved build URLs: %v", [approved_server])
		sugg:="Ensure the artifact is sourced from an approved build server."
		error:=""
		alertStatus := "exception"
	}
