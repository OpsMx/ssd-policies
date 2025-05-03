package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

cluster_id = input.metadata.clusterID
framework = "mitre"

complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/kubescape?clusterID=", cluster_id, "&framework=", framework])
download_url = concat("",["tool-chain/api/v1/kubescape?clusterID=", cluster_id, "&framework=", framework] )

request = {
	"method": "GET",
	"url": complete_url
}

response = http.send(request)
condition_value := input.conditions[0].condition_value
min_threshold_str := split(condition_value, "-")[0]
max_threshold_str := split(condition_value, "-")[1]
min_threshold := to_number(min_threshold_str)
max_threshold := to_number(max_threshold_str)

deny[{"alertMsg":msg, "suggestions": sugg, "error": "", "exception": "", "alertStatus": alertStatus}] {
	score := response.body.compliance_score
	score > min_threshold
	score <= max_threshold
	not policy_name in exception_list
	msg := sprintf("%v Scan failed for cluster %v as Compliance Score was found to be %v which is below threshold %v.", [upper(framework), input.metadata.account_name, score, max_threshold])
	sugg := input.metadata.suggestion
	alertStatus := "active"
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
	score := response.body.compliance_score
	score > min_threshold
	score <= max_threshold
	policy_name in exception_list
	msg := sprintf("%v Scan failed for cluster %v as Compliance Score was found to be %v which is below threshold %v.", [upper(framework), input.metadata.account_name, score, max_threshold])
	sugg := input.metadata.suggestion
	alertStatus := "exception"
}
