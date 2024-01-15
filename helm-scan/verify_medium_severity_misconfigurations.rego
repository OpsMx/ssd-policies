package opsmx
default medium_severities = []

default multi_alert = false
default exists_alert = false

exists_alert = check_if_medium_alert_exists
multi_alert = check_if_multi_alert

check_if_medium_alert_exists = exists_flag {
  medium_severities_counter = count(input.MediumSeverity)
  medium_severities_counter > 0
  exists_flag = true
}

check_if_multi_alert() = multi_flag {
  medium_severities_counter = count(input.MediumSeverity)
  medium_severities_counter > 1
  multi_flag = true
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error }]{
  check_if_medium_alert_exists
  check_if_multi_alert
  
  some i
  rule = input.MediumSeverity[i].RuleID
  title = input.MediumSeverity[i].Title
  targets = concat(",\n", input.MediumSeverity[i].TargetResources)
  resolution = input.MediumSeverity[i].Resolution
  msg := sprintf("Rule ID: %v,\nTitle: %v. \nBelow are the sources of medium severity:\n %v", [rule, title, targets])
  sugg := resolution
  error := ""
}
