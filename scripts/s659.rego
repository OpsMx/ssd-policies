package opsmx

import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scan_account = object.get(object.get(input.metadata, "ssd_secret", {}), "hardware", {"name": "hardware"}).name

artifact_sha = replace(input.metadata.image_sha, ":", "-")
file_name = concat("", [artifact_sha, "-hbomScan.json"])

complete_url = concat("", [input.metadata.toolchain_addr, "api/v1/scanResult?fileName=", file_name, "&scanOperation=hbomscan"])
download_url = concat("", ["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=hbomscan"])

request = {
	"method": "GET",
	"url": complete_url,
}

response = http.send(request)

# Flatten every component in the HBOM tree at any nesting depth (chassis -> PSU/fan/module/...).
all_components := [c |
	walk(response.body, [path, value])
	count(path) > 1
	path[count(path) - 2] == "components"
	is_object(value)
	c := value
]

component_name(ref) = name {
	some c in all_components
	c["bom-ref"] == ref
	name := c.name
} else = ref {
	true
}

is_critical(v) {
	some r in v.ratings
	lower(r.severity) == "critical"
}

is_exception(t) {
	exception_list[_] == t
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": "active", "accountName": scan_account, "justification": ""}] {
	response.status_code == 404
	title := "HBOM Critical Vulnerability: scan result not found"
	msg := sprintf("HBOM scan result not found. Expected file: %v", [file_name])
	error := sprintf("HBOM scan result file not found at %v.", [complete_url])
	sugg := "Ensure the HBOM was successfully ingested by ToolChain before policy evaluation."
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": "active", "accountName": scan_account, "justification": ""}] {
	response.status_code == 500
	title := "HBOM Critical Vulnerability: toolchain error"
	msg := "HBOM scan result could not be fetched due to a toolchain error."
	error := sprintf("Toolchain returned HTTP 500 when fetching HBOM scan result from %v.", [complete_url])
	sugg := "Check if the ToolChain service is available."
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": "active", "accountName": scan_account, "justification": ""}] {
	codes := [200, 404, 500]
	not response.status_code in codes
	title := "HBOM Critical Vulnerability: unexpected response"
	msg := "HBOM scan result could not be fetched."
	error := sprintf("Unexpected HTTP status %v when fetching HBOM scan result.", [response.status_code])
	sugg := "Check the ToolChain service and hbom-generator integration."
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": "", "fileApi": download_url, "exception": "", "alertStatus": "active", "accountName": scan_account, "justification": justification}] {
	response.status_code == 200
	some v in response.body.vulnerabilities
	is_critical(v)
	some a in v.affects
	comp_name := component_name(a.ref)
	title := sprintf("%v — Critical vulnerability %v", [comp_name, v.id])
	not is_exception(title)
	msg := sprintf("Component %v is affected by Critical vulnerability %v.", [comp_name, v.id])
	sugg := sprintf("Remediate or upgrade the firmware/hardware affected by %v.", [v.id])
	justification := object.get(v, "description", "")
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": "", "fileApi": download_url, "exception": title, "alertStatus": "exception", "accountName": scan_account, "justification": justification}] {
	response.status_code == 200
	some v in response.body.vulnerabilities
	is_critical(v)
	some a in v.affects
	comp_name := component_name(a.ref)
	title := sprintf("%v — Critical vulnerability %v", [comp_name, v.id])
	is_exception(title)
	msg := sprintf("Component %v is affected by Critical vulnerability %v.", [comp_name, v.id])
	sugg := sprintf("Remediate or upgrade the firmware/hardware affected by %v.", [v.id])
	justification := object.get(v, "description", "")
}
