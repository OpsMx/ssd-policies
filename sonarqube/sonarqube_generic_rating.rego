package opsmx

import future.keywords.in

rating_map := {
  "A": "5.0",
  "B": "4.0",
  "C": "3.0",
  "D": "2.0",
  "E": "1.0"
}

required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]

request_url = sprintf("%s/api/measures/component?metricKeys=%s&component=%s", [input.metadata.ssd_secret.sonarQube_creds.url, required_rating_name, input.metadata.sonarqube_projectKey])

request = {
    "method": "GET",
    "url": request_url,
    "headers": {
        "Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.sonarQube_creds.token]),
    },
}
default response = ""
response = http.send(request)

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  input.metadata.sonarqube_projectKey == ""
  msg := ""
  error := "Project name not provided."
  sugg := "Verify the integration of Sonarqube in SSD is configured properly."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response == ""
  msg := ""
  error := "Response not received."
  sugg := "Kindly verify the endpoint provided and the reachability of the endpoint."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 500
  msg := ""
  error := "Sonarqube host provided is not reponding or is not reachable." 
  sugg := "Kindly verify the configuration of sonarqube endpoint and reachability of the endpoint."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 404
  msg := ""
  error := sprintf("Error: 404 Not Found. Project not configured for repository %s.", [input.metadata.sonarqube_projectKey])
  sugg := sprintf("Please configure project %s in SonarQube.", [input.metadata.sonarqube_projectKey])
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 403
  error := sprintf("Error: 403 Forbidden. Provided Token does not have privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
  msg := ""
  sugg := sprintf("Kindly verify the access token provided is correct and have required privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  not response.status_code in [500, 404, 403, 200, 302]
  error := sprintf("Error: %v: %v", [response.status_code])
  msg := ""
  sugg := sprintf("Kindly rectify the error while fetching %s project status.", [input.metadata.sonarqube_projectKey])
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code in [200, 302]
  score = response.body.component.measures[0].period.value
  score == required_rating_score
  msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
  sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
  error := ""
}
