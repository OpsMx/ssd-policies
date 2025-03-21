	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	default license_count = 0

	image_sha = replace(input.metadata.image_sha, ":", "-")
	complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", image_sha, "-imageLicenseScanResult.json&scanOperation=imagelicensescan"])
	download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", image_sha, "-imageLicenseScanResult.json&scanOperation=imagelicensescan"] )

	request = {
			"method": "GET",
			"url": complete_url
	}

	response = http.send(request)
	results := response.body.Results

	licenses = [response.body.Results[i].Licenses[j] | count(response.body.Results[i].Licenses) > 0]

	license_count = count(licenses)

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus}]{
			license_count == 0
		    not policy_name in exception_list
			msg := sprintf("Artifact License Scan: No license found to be associated with artifact %v.",[input.metadata.image])
			sugg := "Please associate appropriate license with artifact to be able to evaluate quality of license."
			error := ""
			alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus}]{
			license_count == 0
			policy_name in exception_list
			msg := sprintf("Artifact License Scan: No license found to be associated with artifact %v.",[input.metadata.image])
			sugg := "Please associate appropriate license with artifact to be able to evaluate quality of license."
			error := ""
			alertStatus := "exception"
	}
