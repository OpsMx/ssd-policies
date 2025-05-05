package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

account = input.metadata.account_name

deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of disallowed volume types.", "error": "", "exception": "", "alertStatus": alertStatus, "accountName": account}] {
	not is_update(input.request)

	volume_fields := {x | input.request.object.spec.volumes[_][x]; x != "name"}
	field := volume_fields[_]
	not input_volume_type_allowed(field)
	not policy_name in exception_list
	msg := sprintf("The volume type %v is not allowed, pod: %v. Allowed volume types: %v", [field, input.request.object.metadata.name, input.parameters.volumes])
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of disallowed volume types.", "error": "", "exception": policy_name, "alertStatus": alertStatus, "accountName": account}] {
	not is_update(input.request)

	volume_fields := {x | input.request.object.spec.volumes[_][x]; x != "name"}
	field := volume_fields[_]
	not input_volume_type_allowed(field)
	policy_name in exception_list
	msg := sprintf("The volume type %v is not allowed, pod: %v. Allowed volume types: %v", [field, input.request.object.metadata.name, input.parameters.volumes])
	alertStatus := "exception"
}

# * may be used to allow all volume types
input_volume_type_allowed(_) {
	input.parameters.volumes[_] == "*"
}

input_volume_type_allowed(field) {
	field == input.parameters.volumes[_]
}

is_update(request) {
	request.operation == "UPDATE"
}
