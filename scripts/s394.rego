	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0
	default low_severity_network_issue_count := 0

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

	low_severity_network_findings = [response.body.network_security.network_findings[idx] | response.body.network_security.network_findings[idx].severity == "Low"]
	low_severity_network_issue_count = count(low_severity_network_findings)
	artifact_name := response.body.artifactName

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
		some finding in low_severity_network_findings
		scope := concat(",", finding.scope)
		description := finding.description
		
		not description in exception_list

		title := sprintf("Mobile Application Package Network Issue found in %v", [artifact_name])
		msg := sprintf("Mobile Application Package Manifest Issue found in %v. \n Description: %v \n Components: %v", [artifact_name, description, scope])
		sugg := ""
		error := ""
		alertStatus := "active"
	}

	deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": description, "alertStatus": alertStatus}]{
		some finding in low_severity_network_findings
		scope := concat(",", finding.scope)
		description := finding.description
		
		description in exception_list

		title := sprintf("Mobile Application Package Network Issue found in %v", [artifact_name])
		msg := sprintf("Mobile Application Package Manifest Issue found in %v. \n Description: %v \n Components: %v", [artifact_name, description, scope])
		sugg := ""
		error := ""
		alertStatus := "exception"
	}
