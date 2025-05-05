package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

account = input.metadata.account_name

deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the sharing of host namespaces.", "error": "", "exception": "", "alertStatus": alertStatus, "accountName": account}] {
	not is_update(input.review)

	input_share_hostnamespace(input.request.object)
	not policy_name in exception_list
	msg := sprintf("Sharing the host namespace is not allowed: %v", [input.request.object.metadata.name])
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the sharing of host namespaces.", "error": "", "exception": policy_name, "alertStatus": alertStatus, "accountName": account}] {
	not is_update(input.review)

	input_share_hostnamespace(input.request.object)
	policy_name in exception_list
	msg := sprintf("Sharing the host namespace is not allowed: %v", [input.request.object.metadata.name])
	alertStatus := "exception"
}

input_share_hostnamespace(o) {
	o.spec.hostPID
}
input_share_hostnamespace(o) {
	o.spec.hostIPC
}

is_update(review) {
	review.operation == "UPDATE"
}
