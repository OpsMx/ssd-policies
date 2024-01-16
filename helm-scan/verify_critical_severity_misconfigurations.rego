package opsmx
default critical_severities = []

default multi_alert = false
default exists_alert = false

exists_alert = check_if_critical_alert_exists
multi_alert = check_if_multi_alert

check_if_critical_alert_exists = exists_flag {
  critical_severities_counter = count(input.metadata.results[0].CriticalSeverity)
  critical_severities_counter > 0
  exists_flag = true
}

check_if_multi_alert() = multi_flag {
  critical_severities_counter = count(input.metadata.results[0].CriticalSeverity)
  critical_severities_counter > 1
  multi_flag = true
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error }]{
  check_if_critical_alert_exists
  check_if_multi_alert
  
  some i
  rule = input.metadata.results[0].CriticalSeverity[i].RuleID
  title = input.metadata.results[0].CriticalSeverity[i].Title
  targets = concat(",\n", input.metadata.results[0].CriticalSeverity[i].TargetResources)
  resolution = input.metadata.results[0].CriticalSeverity[i].Resolution
  msg := sprintf("Rule ID: %v,\nTitle: %v. \nBelow are the sources of critical severity:\n %v", [rule, title, targets])
  sugg := resolution
  error := ""
}
