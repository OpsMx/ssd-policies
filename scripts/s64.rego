	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": "Suggest to use only read-only root filesystem container.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)

		c := input_containers[_]
		input_read_only_root_fs(c)
		not policy_name in exception_list
		msg := sprintf("only read-only root filesystem container is allowed: %v", [c.name])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to use only read-only root filesystem container.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)

		c := input_containers[_]
		input_read_only_root_fs(c)
		policy_name in exception_list
		msg := sprintf("only read-only root filesystem container is allowed: %v", [c.name])
		alertStatus := "exception"
	}

	input_read_only_root_fs(c) {
		not has_field(c, "securityContext")
	}
	input_read_only_root_fs(c) {
		not c.securityContext.readOnlyRootFilesystem == true
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

	is_update(request) {
		request.operation == "UPDATE"
	}
