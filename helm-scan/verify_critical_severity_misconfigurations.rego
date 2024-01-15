package opsmx
default critical_severities = []

default multi_alert = false
default exists_alert = false

exists_alert = check_if_critical_alert_exists
multi_alert = check_if_multi_alert

check_if_critical_alert_exists = exists_flag {
  critical_severities_counter = count(input.CriticalSeverity)
  critical_severities_counter > 0
  exists_flag = true
}

check_if_multi_alert() = multi_flag {
  critical_severities_counter = count(input.CriticalSeverity)
  critical_severities_counter > 1
  multi_flag = true
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error }]{
  check_if_critical_alert_exists
  check_if_multi_alert
  
  some i
  rule = input.CriticalSeverity[i].RuleID
  title = input.CriticalSeverity[i].Title
  targets = concat(",\n", input.CriticalSeverity[i].TargetResources)
  resolution = input.CriticalSeverity[i].Resolution
  msg := sprintf("Rule ID: %v,\nTitle: %v. \nBelow are the sources of critical severity:\n %v", [rule, title, targets])
  sugg := resolution
  error := ""
}
