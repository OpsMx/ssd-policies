package opsmx

default secrets_count = 0

request_url = concat("/",[input.metadata.toolchain_addr,"api", "v1", "scanResult?fileName="])
filename_components = [input.metadata.owner, input.metadata.repository, input.metadata.build_id, "codeScanResult.json"]
filename = concat("_", filename_components)

complete_url = concat("", [request_url, filename])

request = {
    "method": "GET",
    "url": complete_url
}

response = http.send(request)

critical_severity_secrets = [response.body.Results[0].Secrets[i].Title | response.body.Results[0].Secrets[i].Severity == "LOW"]
secrets_count = count(critical_severity_secrets)

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  secrets_count > 0

  msg := sprintf("Secret found for %v/%v Github repository for branch %v.\nBelow are the secrets identified:\n %s", [input.metadata.owner, input.metadata.repository, input.metadata.branch, concat(",\n", critical_severity_secrets)])
  sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
  error := ""
}
