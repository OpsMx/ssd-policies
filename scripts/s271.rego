	package opsmx
	import future.keywords.in
	import data.strings

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	body := {
		"image": input.metadata.image,
		"imageTag": input.metadata.image_tag,
		"username": input.metadata.ssd_secret.imageCreds.username,
		"password": input.metadata.ssd_secret.imageCreds.password
	}

	request_url = concat("",[input.metadata.toolchain_addr, "/api", "/v1", "/artifactSign"])

	request = {
		"method": "POST",
		"url": request_url,
		"body": body
	}

	response = http.send(request) 

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus}]{
		response.body.code == 500
		not policy_name in exception_list
		msg = sprintf("Artifact %v:%v is not a signed artifact. Kindly verify authenticity of the artifact and its source.",[input.metadata.image, input.metadata.image_tag])
		sugg := "Kindly use only trusted artifacts in critical environments. To validate trust, the signature must be associated with the artifact."
		error := ""
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": policy_name, "alertStatus": alertStatus}]{
		response.body.code == 500
		policy_name in exception_list
		msg = sprintf("Artifact %v:%v is not a signed artifact. Kindly verify authenticity of the artifact and its source.",[input.metadata.image, input.metadata.image_tag])
		sugg := "Kindly use only trusted artifacts in critical environments. To validate trust, the signature must be associated with the artifact."
		error := ""
		alertStatus := "exception"
	}
