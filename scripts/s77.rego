package opsmx
import future.keywords.in


default exception_list = []
default exception_count = 0

cluster_id = input.metadata.clusterID
framework = "cis-v1.23-t1.0.1"

complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/kubescape?clusterID=", cluster_id, "&framework=", framework])
download_url = concat("",["tool-chain/api/v1/kubescape?clusterID=", cluster_id, "&framework=", framework] )

request = {
	"method": "GET",
	"url": complete_url
}

response = http.send(request)

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

account = input.metadata.account_name

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error, "exception": "", "alertStatus": alertStatus, "accountName": account}] {																																																																
	response.body.results[i].control_title == policy_name
	control_struct = response.body.results[i]
	failed_resources = control_struct.failed_resources
	counter = count(failed_resources)
	counter > 0
	not policy_name in exception_list
	msg := sprintf("%v scan failed for control %v on cluster %v impacting %v resources given below:\n %v", [framework, policy_name, input.metadata.account_name, counter, concat(",\n ",failed_resources)])
	error := ""
	suggestion := input.metadata.suggestion
	alertStatus := "active"
}

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error, "exception": policy_name, "alertStatus": alertStatus, "accountName": account}] {
	response.body.results[i].control_title == policy_name
	control_struct = response.body.results[i]
	failed_resources = control_struct.failed_resources
	counter = count(failed_resources)
	counter > 0
	policy_name in exception_list
	msg := sprintf("%v scan failed for control %v on cluster %v impacting %v resources given below:\n %v", [framework, policy_name, input.metadata.account_name, counter, concat(",\n ",failed_resources)])
	error := ""
	suggestion := input.metadata.suggestion
	alertStatus := "exception"
}
