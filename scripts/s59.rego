package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

account = input.metadata.account_name

deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of HostPath volumes.", "error": "", "exception": "", "alertStatus": alertStatus, "accountName": account}] {
	not is_update(input.request)
	volume := input_hostpath_volumes[_]
	allowedPaths := get_allowed_paths(input)
	input_hostpath_violation(allowedPaths, volume)
	not policy_name in exception_list
	msg := sprintf("HostPath volume %v is not allowed, pod: %v. Allowed path: %v", [volume, input.request.object.metadata.name, allowedPaths])
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": "Suggest to restrict the usage of HostPath volumes.", "error": "", "exception": policy_name, "alertStatus": alertStatus, "accountName": account}] {
	not is_update(input.request)
	volume := input_hostpath_volumes[_]
	allowedPaths := get_allowed_paths(input)
	input_hostpath_violation(allowedPaths, volume)
	policy_name in exception_list
	msg := sprintf("HostPath volume %v is not allowed, pod: %v. Allowed path: %v", [volume, input.request.object.metadata.name, allowedPaths])
	alertStatus := "exception"
}

input_hostpath_violation(allowedPaths, _) {
	allowedPaths == []
}
input_hostpath_violation(allowedPaths, volume) {
	not input_hostpath_allowed(allowedPaths, volume)
}

get_allowed_paths(arg) = out {
	not arg.parameters
	out = []
}
get_allowed_paths(arg) = out {
	not arg.parameters.allowedHostPaths
	out = []
}
get_allowed_paths(arg) = out {
	out = arg.parameters.allowedHostPaths
}

input_hostpath_allowed(allowedPaths, volume) {
	allowedHostPath := allowedPaths[_]
	path_matches(allowedHostPath.pathPrefix, volume.hostPath.path)
	not allowedHostPath.readOnly == true
}

input_hostpath_allowed(allowedPaths, volume) {
	allowedHostPath := allowedPaths[_]
	path_matches(allowedHostPath.pathPrefix, volume.hostPath.path)
	allowedHostPath.readOnly
	not writeable_input_volume_mounts(volume.name)
}

writeable_input_volume_mounts(volume_name) {
	container := input_containers[_]
	mount := container.volumeMounts[_]
	mount.name == volume_name
	not mount.readOnly
}

# This allows "/foo", "/foo/", "/foo/bar" etc., but
# disallows "/fool", "/etc/foo" etc.
path_matches(prefix, path) {
	a := path_array(prefix)
	b := path_array(path)
	prefix_matches(a, b)
}
path_array(p) = out {
	p != "/"
	out := split(trim(p, "/"), "/")
}
# This handles the special case for "/", since
# split(trim("/", "/"), "/") == [""]
path_array("/") = []

prefix_matches(a, b) {
	count(a) <= count(b)
	not any_not_equal_upto(a, b, count(a))
}

any_not_equal_upto(a, b, n) {
	a[i] != b[i]
	i < n
}

input_hostpath_volumes[v] {
	v := input.request.object.spec.volumes[_]
	has_field(v, "hostPath")
}

# has_field returns whether an object has a field
has_field(object, field) = true {
	object[field]
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
