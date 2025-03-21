	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	file_name = concat("", [input.metadata.mobileBuild, "_", input.metadata.image_sha, "_virustotal-mobapp-scan.json"])

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=virusTotalMobAppScan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=virusTotalMobAppScan"])

	request = {	
		"method": "GET",
		"url": complete_url
	}

	response = http.send(request)

	deny [{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some rule in response.body.data.attributes.results
		rule.category == "suspicious"
		engine = rule.engine_name
		engine_version = rule.engine_version
		result = rule.result

		exception_str=concat(":", [engine, result])
		not exception_str in exception_list
	
		title := sprintf("APK/IPA %v scan for rule engine: %v/%v failed with suspicious finding: %v.", [response.body.artifact, engine, engine_version, result])
		msg := sprintf("APK/IPA %v scan for rule engine: %v/%v failed with suspicious finding: %v.", [response.body.artifact, engine, engine_version, result])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny [{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
		some rule in response.body.data.attributes.results
		rule.category == "suspicious"
		engine = rule.engine_name
		engine_version = rule.engine_version
		result = rule.result

		exception_str=concat(":", [engine, result])
		exception_str in exception_list

		title := sprintf("APK/IPA %v scan for rule engine: %v/%v failed with suspicious finding: %v.", [response.body.artifact, engine, engine_version, result])
		msg := sprintf("APK/IPA %v scan for rule engine: %v/%v failed with suspicious finding: %v.", [response.body.artifact, engine, engine_version, result])
		sugg := ""
		error := ""
		exception_cause := exception_str
		alertStatus := "exception"
	}
