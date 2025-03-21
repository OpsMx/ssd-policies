	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		# spec.containers.securityContext.capabilities field is immutable.
		not is_update(input.request)
		container := input.request.object.spec.containers[_]
		has_disallowed_capabilities(container)
		not policy_name in exception_list
		msg := sprintf("container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		# spec.containers.securityContext.capabilities field is immutable.
		not is_update(input.request)
		container := input.request.object.spec.containers[_]
		has_disallowed_capabilities(container)
		policy_name in exception_list
		msg := sprintf("container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)
		container := input.request.object.spec.containers[_]
		missing_drop_capabilities(container)
		not policy_name in exception_list
		msg := sprintf("container <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"", [container.name, input.parameters.requiredDropCapabilities])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)
		container := input.request.object.spec.containers[_]
		missing_drop_capabilities(container)
		policy_name in exception_list
		msg := sprintf("container <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"", [container.name, input.parameters.requiredDropCapabilities])
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)
		container := input.request.object.spec.initContainers[_]
		has_disallowed_capabilities(container)
		not policy_name in exception_list
		msg := sprintf("init container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)
		container := input.request.object.spec.initContainers[_]
		has_disallowed_capabilities(container)
		policy_name in exception_list
		msg := sprintf("init container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)
		container := input.request.object.spec.initContainers[_]
		missing_drop_capabilities(container)
		not policy_name in exception_list
		msg := sprintf("init container <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"", [container.name, input.parameters.requiredDropCapabilities])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)
		container := input.request.object.spec.initContainers[_]
		missing_drop_capabilities(container)
		policy_name in exception_list
		msg := sprintf("init container <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"", [container.name, input.parameters.requiredDropCapabilities])
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)
		container := input.request.object.spec.ephemeralContainers[_]
		has_disallowed_capabilities(container)
		not policy_name in exception_list
		msg := sprintf("ephemeral container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)
		container := input.request.object.spec.ephemeralContainers[_]
		has_disallowed_capabilities(container)
		policy_name in exception_list
		msg := sprintf("ephemeral container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		not is_update(input.request)
		container := input.request.object.spec.ephemeralContainers[_]
		missing_drop_capabilities(container)
		not policy_name in exception_list
		msg := sprintf("ephemeral container <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"", [container.name, input.parameters.requiredDropCapabilities])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the disallowed capabilities of containers.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		not is_update(input.request)
		container := input.request.object.spec.ephemeralContainers[_]
		missing_drop_capabilities(container)
		policy_name in exception_list
		msg := sprintf("ephemeral container <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"", [container.name, input.parameters.requiredDropCapabilities])
		alertStatus := "exception"
	}


	has_disallowed_capabilities(container) {
		allowed := {c | c := lower(input.parameters.allowedCapabilities[_])}
		not allowed["*"]
		capabilities := {c | c := lower(container.securityContext.capabilities.add[_])}

		count(capabilities - allowed) > 0
	}

	missing_drop_capabilities(container) {
		must_drop := {c | c := lower(input.parameters.requiredDropCapabilities[_])}
		all := {"all"}
		dropped := {c | c := lower(container.securityContext.capabilities.drop[_])}

		count(must_drop - dropped) > 0
		count(all - dropped) > 0
	}

	get_default(obj, param, _) = out {
		out = obj[param]
	}

	get_default(obj, param, _default) = out {
		not obj[param]
		not obj[param] == false
		out = _default
	}

	is_update(review) {
			review.operation == "UPDATE"
	}
