package opsmx
import future.keywords.in

default exception_list = []
default exception_count = 0

policy_name = input.metadata.policyName
policy_category = replace(input.metadata.policyCategory, " ", "_")
exception_list = input.metadata.exception[policy_category]

scan_account = input.metadata.ssd_secret.cbomkit.name

default not_quantum_safe_count = 0

image_sha = replace(input.metadata.image_sha, ":", "-")

file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_cbom.json"]) {
	input.metadata.source_code_path == ""
}

file_name = concat("", [input.metadata.owner, "_", input.metadata.repository, "_", input.metadata.build_id, "_", image_sha, "_cbom.json"]) {
	input.metadata.source_code_path != ""
}

complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=", file_name , "&scanOperation=cbomscan"])
download_url = concat("",["tool-chain/api/v1/scanResult?fileName=", file_name, "&scanOperation=cbomscan"])

request = {	
		"method": "GET",
		"url": complete_url
}

response = http.send(request)

get_bom(b) {
    response.body == b
}

# Array of component objects whose complianceLevel == "Not Quantum Safe"
not_quantum_safe_components := [c |
    get_bom(b)
    comps := b.components
    c := comps[_]
    c.complianceLevel == "Not Quantum Safe"
]

# Count of such components
not_quantum_safe_count := count(not_quantum_safe_components)

# helper: return the primitive string if present, otherwise "unknown"
primitive_of(comp) = p {
    comp.cryptoProperties
    comp.cryptoProperties.algorithmProperties
    p := comp.cryptoProperties.algorithmProperties.primitive
}

primitive_of(comp) = "unknown" {
    not comp.cryptoProperties
}

primitive_of(comp) = "unknown" {
    comp.cryptoProperties
    not comp.cryptoProperties.algorithmProperties
}

primitive_of(comp) = "unknown" {
    comp.cryptoProperties
    comp.cryptoProperties.algorithmProperties
    not comp.cryptoProperties.algorithmProperties.primitive
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": "", "alertStatus": alertStatus, "accountName": scan_account}]{
	not_quantum_safe_count > 0
	some i
	comp := not_quantum_safe_components[i]

	# use helper to get primitive or "unknown"
	primitive := primitive_of(comp)

	compliance := comp.complianceMessage
	
	title := sprintf("%v — Non-Quantum-Safe (primitive: %v)", [comp.name, primitive])
	not title in exception_list	
	
	# guarded extraction of a single occurrence's file/line (fallbacks)
	file := comp.evidence.occurrences[_].location {
		comp.evidence
		comp.evidence.occurrences
		comp.evidence.occurrences[_].location
	}
	file := "unknown" {
		not (comp.evidence
		     & comp.evidence.occurrences
		     & comp.evidence.occurrences[_].location)
	}
	line := comp.evidence.occurrences[_].line {
		comp.evidence
		comp.evidence.occurrences
		comp.evidence.occurrences[_].line
	}
	line := "N/A" {
		not (comp.evidence
		     & comp.evidence.occurrences
		     & comp.evidence.occurrences[_].line)
	}

	msg := sprintf(
		"%v uses a non-quantum-safe primitive (%v). Details: %v. Location: %v:%v",
		[comp.name, primitive, compliance, file, line]
	)

	sugg := sprintf(
		"Review usage of %v (%v) and migrate to a quantum-safe or hybrid alternative.",
		[comp.name, primitive]
	)
	error := ""
	alertStatus := "active"
}

deny[{"alertTitle": title, "alertMsg": msg, "suggestion": sugg, "error": error, "fileApi": download_url, "exception": exception_cause, "alertStatus": alertStatus, "accountName": scan_account}]{
	not_quantum_safe_count > 0
	some i
	comp := not_quantum_safe_components[i]

	# use helper to get primitive or "unknown"
	primitive := primitive_of(comp)

	compliance := comp.complianceMessage
	title := sprintf("%v — Non-Quantum-Safe (primitive: %v)", [comp.name, primitive])
	title in exception_list

	# guarded extraction of a single occurrence's file/line (fallbacks)
	file := comp.evidence.occurrences[_].location {
		comp.evidence
		comp.evidence.occurrences
		comp.evidence.occurrences[_].location
	}
	file := "unknown" {
		not (comp.evidence
		     & comp.evidence.occurrences
		     & comp.evidence.occurrences[_].location)
	}
	line := comp.evidence.occurrences[_].line {
		comp.evidence
		comp.evidence.occurrences
		comp.evidence.occurrences[_].line
	}
	line := "N/A" {
		not (comp.evidence
		     & comp.evidence.occurrences
		     & comp.evidence.occurrences[_].line)
	}

	msg := sprintf(
		"%v uses a non-quantum-safe primitive (%v). Details: %v. Location: %v:%v",
		[comp.name, primitive, compliance, file, line]
	)

	sugg := sprintf(
		"Review usage of %v (%v) and migrate to a quantum-safe or hybrid alternative.",
		[comp.name, primitive]
	)
	exception_cause := title
	alertStatus := "exception"
}
