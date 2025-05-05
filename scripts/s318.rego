package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scan_account = input.metadata.ssd_secret.trivy.name

default license_count = 0
default high_severity_licenses = []

image_sha = replace(input.metadata.image_sha, ":", "-")
complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", image_sha, "-imageLicenseScanResult.json&scanOperation=imagelicensescan"])
download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", image_sha, "-imageLicenseScanResult.json&scanOperation=imagelicensescan"] )

request = {
		"method": "GET",
		"url": complete_url
}

response = http.send(request)
results := response.body.Results

licenses = [response.body.Results[i].Licenses[j] | count(response.body.Results[i].Licenses) > 0]

license_count = count(licenses)

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
		license_count == 0
		title := "Artifact License Scan: No license found."
		msg := sprintf("Artifact License Scan: No license found to be associated with artifact %v.",[input.metadata.image])
		sugg := "Please associate appropriate license with artifact to be able to evaluate quality of license."
		error := sprintf("No licenses found to be associated with artifact %v.", [input.metadata.image])
		alertStatus := "error"
}

high_severity_licenses = [licenses[idx] | licenses[idx].Severity == "HIGH"]
high_severity_licenses_with_exception = [high_severity_licenses[idx] | high_severity_licenses[idx].Name in exception_list]
high_severity_licenses_without_exception = [high_severity_licenses[idx] | not high_severity_licenses[idx].Name in exception_list] 


deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
		count(high_severity_licenses_without_exception) > 0
		some i in high_severity_licenses_without_exception
		title := sprintf("Artifact License Scan: Package: %v/ License: %v/ Category: %v", [i.PkgName, i.Name, i.Category])
		msg := sprintf("Artifact License Scan: High Severity License: %v found to be associated with package %v in artifact %v:%v.",[i.Name, i.PkgName, input.metadata.image, input.metadata.image_tag])
		sugg := "Please associate appropriate licenses with code repository and its package dependencies."
		error := ""
		alertStatus := "active" 
		exception := ""
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus, "accountName": scan_account}]{
		count(high_severity_licenses_with_exception) > 0
		some j in high_severity_licenses_with_exception
		title := sprintf("Artifact License Scan: Package: %v/ License: %v/ Category: %v", [j.PkgName, j.Name, j.Category])
		msg := sprintf("Artifact License Scan: High Severity License: %v found to be associated with package %v in artifact %v:%v.",[j.Name, j.PkgName, input.metadata.image, input.metadata.image_tag])
		sugg := "Please associate appropriate licenses with code repository and its package dependencies."
		error := ""
		exception_cause := j.Name
		alertStatus = "exception"
}
