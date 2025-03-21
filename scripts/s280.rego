	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]
	default secrets_count = 0

	default image_name = ""

	image_name = input.metadata.image {
		not contains(input.metadata.image,"/")
	}
	image_name = split(input.metadata.image,"/")[1] {
		contains(input.metadata.image,"/")
	}

	request_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName="])
	image_sha = replace(input.metadata.image_sha, ":", "-")
	filename_components = [image_sha, "imageSecretScanResult.json"]
	filename = concat("-", filename_components)

	complete_url = concat("", [request_url, filename, "&scanOperation=imageSecretScan"])

	request = {
		"method": "GET",
		"url": complete_url
	}

	response = http.send(request)

	medium_severity_secrets = [response.body.Results[0].Secrets[i].Title | response.body.Results[0].Secrets[i].Severity == "MEDIUM"]
	secrets_count = count(medium_severity_secrets)

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		secrets_count > 0
		some i in medium_severity_secrets
		not i in exception_list
		title := sprintf("Medium Severity Secret detected in container: %v", [i])
		msg := sprintf("Secret found for Container %v:%v.\nSecret identified:\n %v", [image_name, input.metadata.image_tag, i])
		sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": exception_cause, "alertStatus": alertStatus}]{
		secrets_count > 0
		some i in medium_severity_secrets
		i in exception_list
		title := sprintf("Medium Severity Secret detected in container: %v", [i])
		msg := sprintf("Secret found for Container %v:%v.\nSecret identified:\n %v", [image_name, input.metadata.image_tag, i])
		sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
		error := ""
		exception_cause := i
		alertStatus := "exception"
	}
