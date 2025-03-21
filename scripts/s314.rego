	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0
	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default license_count = 0
	default critical_severity_licenses = []
	image_sha = replace(input.metadata.image_sha, ":", "-")

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_codeLicenseScanResult.json"]) {
		input.metadata.source_code_path == ""
	}

	file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_codeLicenseScanResult.json"]) {
		input.metadata.source_code_path != ""
	}

	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=codelicensescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=codelicensescan"])

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	results := response.body.Results

	licenses = [results[idx1].Licenses[idx2] | count(results[idx1].Licenses) > 0]

	license_count = count(licenses)

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			license_count == 0
			title := "Code License Scan: No license found."
			msg := sprintf("Code License Scan: No license found to be associated with repository %v:%v.",[input.metadata.owner, input.metadata.repository])
			sugg := "Please associate appropriate license with code repository to be able to evaluate quality of license."
			error := sprintf("No licenses found to be associated with repository %v:%v.", [input.metadata1.owner, input.metadata1.repository])
			alertStatus := "error"
	}

	critical_severity_licenses = [licenses[idx] | licenses[idx].Severity == "CRITICAL"]
	critical_severity_licenses_with_exception = [critical_severity_licenses[idx] | critical_severity_licenses[idx].Name in exception_list]
	critical_severity_licenses_without_exception = [critical_severity_licenses[idx] | not critical_severity_licenses[idx].Name in exception_list] 

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			count(critical_severity_licenses_without_exception) > 0
			some i in critical_severity_licenses_without_exception
			title := sprintf("Code License Scan: Package: %v/ License: %v/ Category: %v", [i.PkgName, i.Name, i.Category])
			msg := sprintf("Code License Scan: Critical Severity License: %v found to be associated with repository %v:%v.",[i.Name, input.metadata.owner, input.metadata.repository])
			sugg := "Please associate appropriate licenses with code repository and its package dependencies."
			error := ""
			alertStatus := "active" 
			exception := ""
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus}]{
			count(critical_severity_licenses_with_exception) > 0
			some j in critical_severity_licenses_with_exception
			title := sprintf("Code License Scan: Package: %v/ License: %v/ Category: %v", [j.PkgName, j.Name, j.Category])
			msg := sprintf("Code License Scan: Critical Severity License: %v found to be associated with repository %v:%v.",[j.Name, input.metadata.owner, input.metadata.repository])
			sugg := "Please associate appropriate licenses with code repository and its package dependencies."
			error := ""
			exception_cause := j.Name
			alertStatus = "exception"
	}
