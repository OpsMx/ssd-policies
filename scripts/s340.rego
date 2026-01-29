package opsmx

default exception_list = []
default exception_count = 0
default issues = []
default count_issues = -1

policy_name := input.metadata.policyName
policy_category := replace(input.metadata.policyCategory, " ", "_")
exception_list := input.metadata.exception[policy_category]

projectId := input.metadata.projectId
projectName := input.metadata.projectName
scanTargetId := input.metadata.scanTargetId
scan_account := input.metadata.ssd_secret.zap.name

image_sha := replace(input.metadata.image_sha, ":", "-")
deployment_id := input.metadata.deploymentId

################################
# URL CONSTRUCTION
################################

complete_url := sprintf(
	"%sapi/v1/scanResult?fileName=%s&scanOperation=zapDastScan",
	[
		input.metadata.toolchain_addr,
		sprintf("%s_%s_%s_zapScan.json", [projectId, projectName, scanTargetId]),
	],
) if {
	projectId != null
	projectId != ""
	scanTargetId != null
	scanTargetId != ""
}

complete_url := sprintf(
	"%sapi/v1/scanResult?fileName=%s&scanOperation=zapDastScan",
	[
		input.metadata.toolchain_addr,
		sprintf("%s_%s_zapScan.json", [image_sha, deployment_id]),
	],
) if {
	projectId == null
} else if {
	projectId == ""
} else if {
	scanTargetId == null
} else if {
	scanTargetId == ""
}

download_url := sprintf(
	"tool-chain/api/v1/scanResult?fileName=%s&scanOperation=zapDastScan",
	[
		sprintf("%s_%s_%s_zapScan.json", [projectId, projectName, scanTargetId]),
	],
) if {
	projectId != null
	projectId != ""
	scanTargetId != null
	scanTargetId != ""
}

download_url := sprintf(
	"tool-chain/api/v1/scanResult?fileName=%s&scanOperation=zapDastScan",
	[
		sprintf("%s_%s_zapScan.json", [image_sha, deployment_id]),
	],
) if {
	projectId == null
} else if {
	projectId == ""
} else if {
	scanTargetId == null
} else if {
	scanTargetId == ""
}

################################

_ := trace(sprintf("DEBUG complete_url: %v", [complete_url]))
debuglog := sprintf("DEBUG download_url: %v", [download_url])

response := http.send({
	"method": "GET",
	"url": complete_url,
})

issues := [a | a := response.body.zapAlerts[_]; a.risk == "Informational"]
count_issues := count(issues)

################################
# DENY
################################

deny contains {
	"alertMsg": "List of High Severity Issues for OWASP ZAP Scan could not be accessed.",
	"suggestion": "Kindly check if the OWASP ZAP is configured properly and SSD has access to the application endpoint.",
	"error": "Failed while fetching issues from OWASP ZAP.",
	"exception": "",
	"alertStatus": "error",
	"accountName": scan_account,
} if {
	count_issues == -1
	msg = "List of High Severity Issues for OWASP ZAP Scan could not be accessed."
	sugg = "Kindly check if the OWASP ZAP is configured properly and SSD has access to the application endpoint."
	error = "Failed while fetching issues from OWASP ZAP."
	alertStatus := "error"
}

deny contains {
	"alertTitle": sprintf("OWASP ZAP Scan: %v", [issues[i].name]),
	"alertMsg": issues[i].description,
	"suggestion": issues[i].solution,
	"error": "",
	"fileApi": download_url,
	"exception": issues[i].name,
	"alertStatus": "exception",
	"accountName": scan_account,
} if {
	some i
	count_issues > 0
	issues[i].name in exception_list
}

deny contains {
	"alertTitle": sprintf("OWASP ZAP Scan: %v", [issues[i].name]),
	"alertMsg": issues[i].description,
	"suggestion": issues[i].solution,
	"error": "",
	"fileApi": download_url,
	"exception": "",
	"alertStatus": "active",
	"accountName": scan_account,
} if {
	some i
	count_issues > 0
	not issues[i].name in exception_list
}