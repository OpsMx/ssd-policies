	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of AppArmor Profiles..", "error": "", "exception": "", "alertStatus": alertStatus}] {
		metadata := input.request.object.metadata
		container := input_containers[_]
		not input_apparmor_allowed(container, metadata)
		not policy_name in exception_list
		msg := sprintf("AppArmor profile is not allowed, pod: %v, container: %v. Allowed profiles: %v", [input.request.object.metadata.name, container.name, input.parameters.allowedProfiles])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of AppArmor Profiles..", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		metadata := input.request.object.metadata
		container := input_containers[_]
		not input_apparmor_allowed(container, metadata)
		policy_name in exception_list
		msg := sprintf("AppArmor profile is not allowed, pod: %v, container: %v. Allowed profiles: %v", [input.request.object.metadata.name, container.name, input.parameters.allowedProfiles])
		alertStatus := "exception"
	}

	input_apparmor_allowed(container, metadata) {
		get_annotation_for(container, metadata) == input.parameters.allowedProfiles[_]
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

	get_annotation_for(container, metadata) = out {
		out = metadata.annotations[sprintf("container.apparmor.security.beta.kubernetes.io/%v", [container.name])]
	}
	get_annotation_for(container, metadata) = out {
		not metadata.annotations[sprintf("container.apparmor.security.beta.kubernetes.io/%v", [container.name])]
		out = "runtime/default"
	}
