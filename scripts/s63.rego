	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of restricted ProcMount types.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)

		c := input_containers[_]
		allowedProcMount := get_allowed_proc_mount(input)
		not input_proc_mount_type_allowed(allowedProcMount, c)
		not policy_name in exception_list
		msg := sprintf("ProcMount type is not allowed, container: %v. Allowed procMount types: %v", [c.name, allowedProcMount])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of restricted ProcMount types.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)

		c := input_containers[_]
		allowedProcMount := get_allowed_proc_mount(input)
		not input_proc_mount_type_allowed(allowedProcMount, c)
		policy_name in exception_list
		msg := sprintf("ProcMount type is not allowed, container: %v. Allowed procMount types: %v", [c.name, allowedProcMount])
		alertStatus := "exception"
	}

	input_proc_mount_type_allowed(allowedProcMount, c) {
		allowedProcMount == "default"
		lower(c.securityContext.procMount) == "default"
	}
	input_proc_mount_type_allowed(allowedProcMount, _) {
		allowedProcMount == "unmasked"
	}

	input_containers[c] {
		c := input.request.object.spec.containers[_]
		c.securityContext.procMount
	}
	input_containers[c] {
		c := input.request.object.spec.initContainers[_]
		c.securityContext.procMount
	}
	input_containers[c] {
		c := input.request.object.spec.ephemeralContainers[_]
		c.securityContext.procMount
	}

	get_allowed_proc_mount(arg) = out {
		not arg.parameters
		out = "default"
	}
	get_allowed_proc_mount(arg) = out {
		not arg.parameters.procMount
		out = "default"
	}
	get_allowed_proc_mount(arg) = out {
		arg.parameters.procMount
		not valid_proc_mount(arg.parameters.procMount)
		out = "default"
	}
	get_allowed_proc_mount(arg) = out {
		valid_proc_mount(arg.parameters.procMount)
		out = lower(arg.parameters.procMount)
	}

	valid_proc_mount(str) {
		lower(str) == "default"
	}
	valid_proc_mount(str) {
		lower(str) == "unmasked"
	}

	is_update(request) {
		request.operation == "UPDATE"
	}
