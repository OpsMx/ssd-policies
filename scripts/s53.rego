	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of privilege escalation containers.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)
		not policy_name in exception_list
		c := input_containers[_]
		input_allow_privilege_escalation(c)
		msg := sprintf("Privilege escalation container is not allowed: %v", [c.name])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of privilege escalation containers.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)
		policy_name in exception_list
		c := input_containers[_]
		input_allow_privilege_escalation(c)
		msg := sprintf("Privilege escalation container is not allowed: %v", [c.name])
		alertStatus := "exception"
	}

	input_allow_privilege_escalation(c) {
		not has_field(c, "securityContext")
	}
	input_allow_privilege_escalation(c) {
		not c.securityContext.allowPrivilegeEscalation == false
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

	has_field(object, field) = true {
		object[field]
	}

	is_update(review) {
		review.operation == "UPDATE"
	}
