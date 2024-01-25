package opsmx
import future.keywords.in

default allow = false

request_components = [input.metadata.ssd_secret.gitlab.rest_api_url,"api/v4/user"]

request_url = concat("/",request_components)

token = input.metadata.token

request = {
    "method": "GET",
    "url": request_url,
    "headers": {
        "PRIVATE-TOKEN": sprintf("%v", [token]),
    },
}

response = http.send(request)

allow {
  response.status_code = 200
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  codes = [401, 404, 500, 200, 301, 302]
  response.status_code in codes
  msg := "Unable to fetch repository configuration."
  error := sprintf("Error %v receieved from Gitlab upon trying to fetch Repository Configuration.", [response.body.message])
  sugg := "Kindly check Gitlab API is reachable and the provided access token has required permissions."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.body.two_factor_enabled = false
  msg := sprintf("Gitlab Organisation %v doesn't have the mfa enabled.", [input.metadata.owner])
  sugg := sprintf("Adhere to the company policy by enabling 2FA for %s.",[input.metadata.owner])
  error := ""
}
