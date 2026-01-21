package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0
default remediation := ""
default references := ""
default policy_suggestion := ""

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scan_account = input.metadata.ssd_secret.aws.name

default findings_count = 0

cloud_account_name := input.metadata.cloudAccountName
results := input.metadata.cspmFindings

flagged_items = results.flagged_items
rule_description := results.description
rule_name := results.name
rule_rationale = results.rationale
references = concat(" \n", results.references)
remediation = results.remediation
policy_suggestion = input.metadata.suggestion


deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "cspmEnrichedFinding": cspmEnrichedFinding, "cspmIsService": cspmIsService, "accountName": scan_account}]{
		flagged_items > 0
		not rule_name in exception_list
		some i
		violated_resource := results.affectedResources[i].name
		cspmEnrichedFinding := results.affectedResources[i].id
		cspmIsService := results.affectedResources[i].affectedAttributes == "service-finding-list"
		service_type := results.service

		title := sprintf("Rule: %v violated for %v resource %v", [rule_name, service_type, violated_resource])
		msg := sprintf("Rule: %v violated for %v resource %v. \nRule Description: %v. \n Detailed Description: %v.", [rule_name, service_type, violated_resource, rule_description, rule_rationale])
		error := ""
		sugg := sprintf("%v \n %v \n %v", [policy_suggestion, remediation, references])
		alertStatus := "active"
}

deny[{ "alertStatus": alertStatus, "cspmEnrichedFinding": cspmEnrichedFinding, "cspmIsService": cspmIsService, "accountName": scan_account}]{
		flagged_items == 0
		some i
		cspmEnrichedFinding := results.affectedResources[i].id
		cspmIsService := results.affectedResources[i].affectedAttributes == "service-finding-list"
		
		alertStatus := "passed"
}


deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "exception": exception_cause, "alertStatus": alertStatus, "cspmEnrichedFinding": cspmEnrichedFinding, "cspmIsService": cspmIsService, "accountName": scan_account}]{
		flagged_items > 0
		rule_name in exception_list
		some i
		violated_resource := results.affectedResources[i].name
		cspmEnrichedFinding := results.affectedResources[i].id
		cspmIsService := results.affectedResources[i].affectedAttributes == "service-finding-list"
		service_type := results.service

		title := sprintf("Rule: %v violated for %v resource %v", [rule_name, service_type, violated_resource])
		msg := sprintf("Rule: %v violated for %v resource %v. \nRule Description: %v. \n Detailed Description: %v.", [rule_name, service_type, violated_resource, rule_description, rule_rationale])
		error := ""
		sugg := sprintf("%v \n %v \n %v", [policy_suggestion, remediation, references])
		exception_cause := rule_name
		alertStatus := "exception"
}
