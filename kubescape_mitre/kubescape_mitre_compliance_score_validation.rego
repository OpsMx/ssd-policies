package opsmx

condition_value := input.conditions[0].condition_value
min_threshold_str := split(condition_value, "-")[0]
max_threshold_str := split(condition_value, "-")[1]
min_threshold := to_number(min_threshold_str)
max_threshold := to_number(max_threshold_str)

deny[{"alertMsg":msg, "suggestions": sugg, "error": ""}] {
  score := input.metadata.compliance_score
  score > min_threshold
  score <= max_threshold
  msg := sprintf("%v Scan failed for cluster %v as Compliance Score was found to be %v which is below threshold %v.", [input.metadata.scan_type, input.metadata.account_name, score, max_threshold])
  sugg := input.metadata.suggestion
}
