	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.mobileBuild, "_", image_sha, "_mobsfscan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=mobsfScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=mobsfScan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)


	artifact_name = response.body.artifactName


	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some key
		finding := response.body.macho_analysis[key]
		key != "name"
		finding.severity == "High"

		not key in exception_list

		desc := finding.description
		title := sprintf("Macho Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		msg := sprintf("Macho Analysis Failure in artifact: %v \n Description: %v", [artifact_name, desc])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		some key
		finding := response.body.macho_analysis[key]
		key != "name"
		finding.severity == "High"

		key in exception_list

		desc := finding.description
		title := sprintf("Macho Analysis Failure in artifact: %v for rule: %v", [artifact_name, key])
		msg := sprintf("Macho Analysis Failure in artifact: %v \n Description: %v", [artifact_name, desc])
		sugg := ""
		error := ""
		exception_cause := key
		alertStatus := "active"
	}
