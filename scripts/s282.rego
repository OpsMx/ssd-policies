package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scan_account = input.metadata.ssd_secret.helmScan.name

severity = "high"
default findings_count = 0

chart_name = input.metadata.chartName
chart_version = input.metadata.chartVersion
helm_tool = input.metadata.helmTool

complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=helm-", chart_name, "-", chart_version, "-", helm_tool, "-", severity, ".json&scanOperation=helmscan"]	)
download_url = concat("",["tool-chain/api/v1/scanResult?fileName=helm-", chart_name, "-", chart_version, "-", helm_tool, "-", severity, ".json&scanOperation=helmscan"])

request = {	
		"method": "GET",
		"url": complete_url
}

response = http.send(request)
findings = response.body.helmAnalysis

findings_count = count(findings)

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	findings_count > 0
	some i
	rule_id := findings[i].RuleID
	impacted_components := concat(",\n ", findings[i].TargetResources)
	not rule_id in exception_list
	title := sprintf("Rule %v: %v found violated in helm chart %v:%v", [findings[i].Title, findings[i].RuleID, chart_name, chart_version])
	msg := sprintf("Rule %v: %v found violated in helm chart %v:%v with following impacted resources: %v", [findings[i].Title, findings[i].RuleID, chart_name, chart_version, impacted_components])
	error := ""
	sugg := findings[i].Resolution
	alertStatus := "active"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus, "accountName": scan_account}]{
	findings_count > 0
	some i
	rule_id := findings[i].RuleID
	impacted_components := concat(",\n ", findings[i].TargetResources)
	rule_id in exception_list
	title := sprintf("Rule %v: %v found violated in helm chart %v:%v", [findings[i].Title, findings[i].RuleID, chart_name, chart_version])
	msg := sprintf("Rule %v: %v found violated in helm chart %v:%v with following impacted resources: %v", [findings[i].Title, findings[i].RuleID, chart_name, chart_version, impacted_components])
	error := ""
	sugg := findings[i].Resolution
	exception_cause := findings[i].rule_name
	alertStatus := "exception"
}
