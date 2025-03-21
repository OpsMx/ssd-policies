	package opsmx
	severities = ["MODERATE","UNDEFINED","MEDIUM","UNKNOWN"]
	vuln_id = input.conditions[0].condition_value
	vuln_severity = {input.conditions[i].condition_value | input.conditions[i].condition_name = "severity"}
	deny[msg]{
		some i
		inputSeverity = severities[i]
		some j
		vuln_severity[j] == inputSeverity 
		msg:= sprintf("%v Criticality Vulnerability : %v found in plugin: %v", [inputSeverity, vuln_id, input.metadata.plugin_name])
	}
