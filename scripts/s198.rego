	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	policy = input.conditions[0].condition_name
	control_id = split(policy, " -")[0]


	deny[{"alertMsg":msg, "suggestion":suggestion, "error":"", "exception": "", "alertStatus": alertStatus}] {
		input.metadata.results[i].control_id == control_id
		control_struct = input.metadata.results[i]
		failed_resources = control_struct.failed_resources
		counter = count(failed_resources)
		counter > 0
		not policy_name in exception_list
		msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
		suggestion := input.metadata.suggestion
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestion":suggestion, "error":"", "exception": policy_name, "alertStatus": alertStatus}] {
		input.metadata.results[i].control_id == control_id
		control_struct = input.metadata.results[i]
		failed_resources = control_struct.failed_resources
		counter = count(failed_resources)
		counter > 0
		policy_name in exception_list
		msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
		suggestion := input.metadata.suggestion
		alertStatus := "exception"
	}
