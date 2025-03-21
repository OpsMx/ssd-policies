	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of Flex Volumes.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		# spec.volumes field is immutable.
		not is_update(input.request)

		volume := input_flexvolumes[_]
		not input_flexvolumes_allowed(volume)
		not policy_name in exception_list
		msg := sprintf("FlexVolume %v is not allowed, pod: %v. Allowed drivers: %v", [volume, input.request.object.metadata.name, input.parameters.allowedFlexVolumes])
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of Flex Volumes.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		# spec.volumes field is immutable.
		not is_update(input.request)

		volume := input_flexvolumes[_]
		not input_flexvolumes_allowed(volume)
		policy_name in exception_list
		msg := sprintf("FlexVolume %v is not allowed, pod: %v. Allowed drivers: %v", [volume, input.request.object.metadata.name, input.parameters.allowedFlexVolumes])
		alertStatus := "exception"
	}

	input_flexvolumes_allowed(volume) {
		input.parameters.allowedFlexVolumes[_].driver == volume.flexVolume.driver
	}

	input_flexvolumes[v] {
		v := input.request.object.spec.volumes[_]
		has_field(v, "flexVolume")
	}

	# has_field returns whether an object has a field
	has_field(object, field) = true {
		object[field]
	}

	is_update(review) {
		review.operation == "UPDATE"
	}
