package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

account = input.metadata.account_name

deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of hostNetwork and hostPort.", "error": "", "exception": "", "alertStatus": alertStatus, "accountName": account}] {
	not is_update(input.request)

	input_share_hostnetwork(input.request.object)
	not policy_name in exception_list
	msg := sprintf("The specified hostNetwork and hostPort are not allowed, pod: %v. Allowed values: %v", [input.request.object.metadata.name, input.parameters])
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of hostNetwork and hostPort.", "error": "", "exception": policy_name, "alertStatus": alertStatus, "accountName": account}] {
	not is_update(input.request)

	input_share_hostnetwork(input.request.object)
	policy_name in exception_list
	msg := sprintf("The specified hostNetwork and hostPort are not allowed, pod: %v. Allowed values: %v", [input.request.object.metadata.name, input.parameters])
	alertStatus := "exception"
}

input_share_hostnetwork(o) {
	not input.parameters.hostNetwork
	o.spec.hostNetwork
}

input_share_hostnetwork(_) {
	hostPort := input_containers[_].ports[_].hostPort
	hostPort < input.parameters.min
}

input_share_hostnetwork(_) {
	hostPort := input_containers[_].ports[_].hostPort
	hostPort > input.parameters.max
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

is_update(request) {
	request.operation == "UPDATE"
}
