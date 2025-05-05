package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

account = input.metadata.account_name

# Block if forbidden
deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of restricted sysctls in security context.", "error": "", "exception": "", "alertStatus": alertStatus, "accountName": account}] {
	# spec.securityContext.sysctls field is immutable.
	not is_update(input.request)

	sysctl := input.request.object.spec.securityContext.sysctls[_].name
	forbidden_sysctl(sysctl)
	not policy_name in exception_list
	msg := sprintf("The sysctl %v is not allowed, pod: %v. Forbidden sysctls: %v", [sysctl, input.request.object.metadata.name, input.parameters.forbiddenSysctls])
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of restricted sysctls in security context.", "error": "", "exception": policy_name, "alertStatus": alertStatus, "accountName": account}] {
	# spec.securityContext.sysctls field is immutable.
	not is_update(input.request)

	sysctl := input.request.object.spec.securityContext.sysctls[_].name
	forbidden_sysctl(sysctl)
	policy_name in exception_list
	msg := sprintf("The sysctl %v is not allowed, pod: %v. Forbidden sysctls: %v", [sysctl, input.request.object.metadata.name, input.parameters.forbiddenSysctls])
	alertStatus := "exception"
}

# Block if not explicitly allowed
deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of restricted sysctls in security context.", "error": "", "exception": "", "alertStatus": alertStatus, "accountName": account}] {
	not is_update(input.request)
	sysctl := input.request.object.spec.securityContext.sysctls[_].name
	not allowed_sysctl(sysctl)
	not policy_name in exception_list
	msg := sprintf("The sysctl %v is not explicitly allowed, pod: %v. Allowed sysctls: %v", [sysctl, input.request.object.metadata.name, input.parameters.allowedSysctls])
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of restricted sysctls in security context.", "error": "", "exception": policy_name, "alertStatus": alertStatus, "accountName": account}] {
	not is_update(input.request)
	sysctl := input.request.object.spec.securityContext.sysctls[_].name
	not allowed_sysctl(sysctl)
	policy_name in exception_list
	msg := sprintf("The sysctl %v is not explicitly allowed, pod: %v. Allowed sysctls: %v", [sysctl, input.request.object.metadata.name, input.parameters.allowedSysctls])
	alertStatus := "exception"
}

# * may be used to forbid all sysctls
forbidden_sysctl(sysctl) {
	input.parameters.forbiddenSysctls[_] == "*"
}

forbidden_sysctl(sysctl) {
	input.parameters.forbiddenSysctls[_] == sysctl
}

forbidden_sysctl(sysctl) {
	forbidden := input.parameters.forbiddenSysctls[_]
	endswith(forbidden, "*")
	startswith(sysctl, trim_suffix(forbidden, "*"))
}

# * may be used to allow all sysctls
allowed_sysctl(sysctl) {
	input.parameters.allowedSysctls[_] == "*"
}

allowed_sysctl(sysctl) {
	input.parameters.allowedSysctls[_] == sysctl
}

allowed_sysctl(sysctl) {
	allowed := input.parameters.allowedSysctls[_]
	endswith(allowed, "*")
	startswith(sysctl, trim_suffix(allowed, "*"))
}

is_update(request) {
		request.operation == "UPDATE"
}
