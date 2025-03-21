	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	input_stages = input.metadata.stages
	manualJudgment_stages = [input.metadata.stages[i] | input.metadata.stages[i].type == "manualJudgment"]
	counter = count(manualJudgment_stages)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": "", "exception": "", "alertStatus": alertStatus}]{
		count(manualJudgment_stages) < 1
		not policy_name in exception_list
		msg := "No manual judgement stages configured in pipeline."
		sugg := "Kindly follow security best practices by introducing manual judgement stage before deployment to critical environments."
		alertStatus := "active"
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": "", "exception": policy_name, "alertStatus": alertStatus}]{
		count(manualJudgment_stages) < 1
		policy_name in exception_list
		msg := "No manual judgement stages configured in pipeline."
		sugg := "Kindly follow security best practices by introducing manual judgement stage before deployment to critical environments."
		alertStatus := "exception"
	}
