package opsmx
import future.keywords.in

openssf_results_file = concat("_", [input.metadata.owner, input.metadata.repository, input.metadata.build_id])
openssf_results_file_complete = concat("", [openssf_results_file, "_scorecard.json"])

policy_name = input.conditions[0].condition_name 
check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")

check_name = replace(lower(check_orig), " ", "-")
threshold = to_number(input.conditions[0].condition_value)
request_url = concat("",[input.metadata.toolchain_addr, "/api", "/v1", "/openssfScore?scoreCardName=", openssf_results_file_complete, "&", "checkName=", check_name])

request = {
    "method": "GET",
    "url": request_url,
}

response = http.send(request)


deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.body.code == 404
  msg := ""
  sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
  error := sprintf("Error Received: %v.",[response.body.error])
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 500
  msg := ""
  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
  error := sprintf("Error Received: %v.",[response.body.error])
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  codes = [401, 404, 500, 200, 302]
  not response.status_code in codes
  msg := ""
  error := sprintf("Error %v receieved: %v", [response.body.error])
  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
}

default in_range = false

isNumberBetweenTwoNumbers(num, lower, upper) {
    num >= lower
    num <= upper
}

in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)

deny[{{"alertMsg":msg, "suggestions": sugg, "error": error}}]{
  in_range == true
  response.body.score < threshold

  documentation := response.body.documentation 
  msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
  sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
  error := ""
}
