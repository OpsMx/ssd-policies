package opsmx
import future.keywords.in

request_url_p1 = concat("/",[input.metadata.ssd_secret.sonarQube_creds.url,"api/qualitygates/project_status?projectKey"])
request_url = concat("=", [request_url_p1, input.metadata.sonarqube_projectKey])


request = {
    "method": "GET",
    "url": request_url,
    "headers": {
        "Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.sonarQube_creds.token]),
    },
}

default response = ""
response = http.send(request)

eny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
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
  response.body.projectStatus.status == "ERROR"
  msg := sprintf("SonarQube Quality Gate Status Check has failed for project %s. Prioritize and address the identified issues promptly to meet the defined quality standards and ensure software reliability.", [input.metadata.sonarqube_projectKey])
  error := ""
  sugg := "Prioritize and address the identified issues promptly to meet the defined quality standards and ensure software reliability."
}
