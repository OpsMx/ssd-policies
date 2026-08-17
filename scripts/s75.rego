package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scan_account = input.metadata.ssd_secret.sonarqube.name

default score = ""

rating_map := {
	"A": "1.0",
	"B": "2.0",
	"C": "3.0",
	"D": "4.0",
	"E": "5.0"
}

required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]

image_sha = replace(input.metadata.image_sha, ":", "-")

file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_sonarqube.json"]) {
	input.metadata.source_code_path == ""
}

file_name = concat("", ["analysis_", input.metadata.owner, "_", input.metadata.sonarqube_projectKey, "_", input.metadata.build_id, "_", image_sha, "_sonarqube.json"]) {
	input.metadata.source_code_path != ""
}

complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name, "&scanOperation=sonarqubescan"])
download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name ,"&scanOperation=sonarqubescan"] )

request = {
		"method": "GET",
		"url": complete_url
}

response = http.send(request)
score = [response.measures[i].period.value | response.measures[i].metric == "new_reliability_rating"][0]

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	score == ""
	msg := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
	sugg := "Kindly verify if the token provided has permissions to read the quality metrics. Also, verify if the required quality metrics are available for the project."
	error := sprintf("Required Metric %v for sonarqube project could not be obtained.", [required_rating_name])
	alertStatus := "error"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	score == required_rating_score
	not policy_name in exception_list
	msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
	sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
	error := ""
	alertStatus := "active"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": policy_name, "alertStatus": alertStatus, "accountName": scan_account}]{
	score == required_rating_score
	policy_name in exception_list
	msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
	sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
	error := ""
	alertStatus := "exception"
}
