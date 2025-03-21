	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default facetvalues := []

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_sonarqube.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_", image_sha, "_sonarqube.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name, "&scanOperation=sonarqubescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name ,"&scanOperation=sonarqubescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	facetvalues := response.body.facets[_].values

	critical_count := [facetvalues[i].count | facetvalues[i].val == "CRITICAL"]
	blocker_count := [facetvalues[i].count | facetvalues[i].val == "BLOCKER"]

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		count(facetvalues) == 0
		msg = "No facet values found for severities."
		sugg = "Kindly check if the Sonarqube token is configured and has permissions to read issues of the project."
		error = "Failed while fetching severity count from Sonarqube."
		alertStatus := "error"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		count(facetvalues) > 0
		critical_count[0] > 0
		not policy_name in exception_list
		msg = sprintf("Blocker or Critical issues found during SAST scan for repository %v/%v and branch %v. \nBlocker Issues: %v \nCritical Issues: %v", [input.metadata.owner, input.metadata.repository, input.metadata.branch, blocker_count[0], critical_count[0]])
		sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
		error = ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		count(facetvalues) > 0
		critical_count[0] > 0
		policy_name in exception_list
		msg = sprintf("Blocker or Critical issues found during SAST scan for repository %v/%v and branch %v. \nBlocker Issues: %v \nCritical Issues: %v", [input.metadata.owner, input.metadata.repository, input.metadata.branch, blocker_count[0], critical_count[0]])
		sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
		error = ""
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		count(facetvalues) > 0
		blocker_count[0] > 0
		not policy_name in exception_list
		msg = sprintf("Blocker or Critical issues found during SAST scan for repository %v/%v and branch %v. \nBlocker Issues: %v \nCritical Issues: %v", [input.metadata.owner, input.metadata.repository, input.metadata.branch, blocker_count[0], critical_count[0]])
		sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
		error = ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
		count(facetvalues) > 0
		blocker_count[0] > 0
		policy_name in exception_list
		msg = sprintf("Blocker or Critical issues found during SAST scan for repository %v/%v and branch %v. \nBlocker Issues: %v \nCritical Issues: %v", [input.metadata.owner, input.metadata.repository, input.metadata.branch, blocker_count[0], critical_count[0]])
		sugg = "Kindly refer to the list of issues reported in SAST scan and their resolutions."
		error = ""
		alertStatus := "exception"
	}
