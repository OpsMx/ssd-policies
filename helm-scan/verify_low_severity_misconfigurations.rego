package opsmx
default low_severities = []

default multi_alert = false
default exists_alert = false

exists_alert = check_if_low_alert_exists
multi_alert = check_if_multi_alert

check_if_low_alert_exists = exists_flag {
  low_severities_counter = count(input.metadata.results.LowSeverity)
  low_severities_counter > 0
  exists_flag = true
}

check_if_multi_alert() = multi_flag {
  low_severities_counter = count(input.metadata.results.LowSeverity)
  low_severities_counter > 1
  multi_flag = true
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error }]{
  check_if_low_alert_exists
  check_if_multi_alert
  
  some i
  rule = input.metadata.results.LowSeverity[i].RuleID
  title = input.metadata.results.LowSeverity[i].Title
  targets = concat(",\n", input.metadata.results.LowSeverity[i].TargetResources)
  resolution = input.metadata.results.LowSeverity[i].Resolution
  msg := sprintf("Rule ID: %v,\nTitle: %v. \nBelow are the sources of low severity:\n %v", [rule, title, targets])
  sugg := resolution
  error := ""
}
