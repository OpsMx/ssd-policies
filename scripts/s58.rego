package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

account = input.metadata.account_name

deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of fsGroup in security context.", "error": "", "exception": "", "alertStatus": alertStatus, "accountName": account}] {
	# spec.securityContext.fsGroup field is immutable.
	not is_update(input.request)

	spec := input.request.object.spec
	not input_fsGroup_allowed(spec)
	not policy_name in exception_list
	msg := sprintf("The provided pod spec fsGroup is not allowed, pod: %v. Allowed fsGroup: %v", [input.request.object.metadata.name, input.parameters])
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of fsGroup in security context.", "error": "", "exception": policy_name, "alertStatus": alertStatus, "accountName": account}] {
	# spec.securityContext.fsGroup field is immutable.
	not is_update(input.request)

	spec := input.request.object.spec
	not input_fsGroup_allowed(spec)
	policy_name in exception_list
	msg := sprintf("The provided pod spec fsGroup is not allowed, pod: %v. Allowed fsGroup: %v", [input.request.object.metadata.name, input.parameters])
	alertStatus := "exception"
}

input_fsGroup_allowed(_) {
	# RunAsAny - No range is required. Allows any fsGroup ID to be specified.
	input.parameters.rule == "RunAsAny"
}
input_fsGroup_allowed(spec) {
	# MustRunAs - Validates pod spec fsgroup against all ranges
	input.parameters.rule == "MustRunAs"
	fg := spec.securityContext.fsGroup
	count(input.parameters.ranges) > 0
	range := input.parameters.ranges[_]
	value_within_range(range, fg)
}
input_fsGroup_allowed(spec) {
	# MayRunAs - Validates pod spec fsgroup against all ranges or allow pod spec fsgroup to be left unset
	input.parameters.rule == "MayRunAs"
	not has_field(spec, "securityContext")
}
input_fsGroup_allowed(spec) {
	# MayRunAs - Validates pod spec fsgroup against all ranges or allow pod spec fsgroup to be left unset
	input.parameters.rule == "MayRunAs"
	not spec.securityContext.fsGroup
}
input_fsGroup_allowed(spec) {
	# MayRunAs - Validates pod spec fsgroup against all ranges or allow pod spec fsgroup to be left unset
	input.parameters.rule == "MayRunAs"
	fg := spec.securityContext.fsGroup
	count(input.parameters.ranges) > 0
	range := input.parameters.ranges[_]
	value_within_range(range, fg)
}
value_within_range(range, value) {
	range.min <= value
	range.max >= value
}
# has_field returns whether an object has a field
has_field(object, field) = true {
	object[field]
}

is_update(request) {
	request.operation == "UPDATE"
}
