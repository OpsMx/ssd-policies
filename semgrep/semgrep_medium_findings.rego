package opsmx

severity = "medium"
default findings_count = 0
request_components = [input.metadata.toolchain_addr,"api", "v1", "scanResult"]
request_url = concat("/",request_components)
filename_components = ["fileName=findings", input.metadata.owner, input.metadata.repository, severity, input.metadata.build_id, "semgrep.json"]
filename = concat("_", filename_components)

complete_url = concat("?", [request_url, filename])

request = {
    "method": "GET",
    "url": complete_url
}

response = http.send(request)

findings_count = response.body.totalFindings

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  findings_count > 0
  msg := sprintf("The github repository %v/%v contains %v findings of %v severity.", [input.metadata.owner, input.metadata.repository, findings_count, severity])
  sugg := "Please examine the medium-severity findings in the SEMGREP analysis data, available through the View Findings button & proactively review your code for common issues and apply best coding practices during development to prevent such alerts from arising."
  error := ""
}
