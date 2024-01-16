package opsmx

default secrets_count = 0

default image_name = ""

image_name = input.metadata.image {
    not contains(input.metadata.image,"/")
}
image_name = split(input.metadata.image,"/")[1] {
    contains(input.metadata.image,"/")
}

request_url = concat("/",[input.metadata.toolchain_addr,"api", "v1", "scanResult?fileName="])
filename_components = [image_name, input.metadata.image_tag, "imageScanResult.json"]
filename = concat("_", filename_components)

complete_url = concat("", [request_url, filename])

request = {
    "method": "GET",
    "url": complete_url
}

response = http.send(request)

high_severity_secrets = [response.body.Results[0].Secrets[i].Title | response.body.Results[0].Secrets[i].Severity == "HIGH"]
secrets_count = count(high_severity_secrets)

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  secrets_count > 0

  msg := sprintf("Secret found for Artifact %v:%v.\nBelow are the secrets identified:\n %v", [image_name, input.metadata.image_tag, concat(",\n", high_severity_secrets)])
  sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
  error := ""
}
