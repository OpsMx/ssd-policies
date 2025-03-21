	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of privileged containers in security context.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)

		c := input_containers[_]
		c.securityContext.privileged
		not policy_name in exception_list
		msg := sprintf("Privileged container is not allowed: %v, securityContext: %v", [c.name, c.securityContext])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of privileged containers in security context.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)

		c := input_containers[_]
		c.securityContext.privileged
		policy_name in exception_list
		msg := sprintf("Privileged container is not allowed: %v, securityContext: %v", [c.name, c.securityContext])
		alertStatus := "exception"
	}

	input_containers[c] {
		c := input.request.object.spec.containers[_]
	}

	input_containers[c] {
		c := input.request.object.spec.initContainers[_]
	}

	input_containers[c] {
		c := input.request.object.spec.ephemeralContainers[_]
	}

	is_update(request) {
		request.operation == "UPDATE"
	}
