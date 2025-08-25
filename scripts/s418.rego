package opsmx
import future.keywords.in

default allow = false

request = {
    "method": "GET",
    "url": "https://mpa54fc1c3be56479493.free.beeceptor.com/api/testexec/TEST-123/test?detailed=true"
}

response = http.send(request)

# Handle HTTP errors
deny[{
    "alertMsg": msg,
    "suggestions": sugg,
    "error": error,
    "exception": "",
    "alertStatus": "error",
    "accountName": "",
    "http_status": response.status_code,
    "response_body": response.body
}] {
    response.status_code == 401
    msg = "Unauthorized to access test execution API"
    error = "401 Unauthorized: Invalid credentials or permissions"
    sugg = "Check API authentication credentials and permissions"
}

deny[{
    "alertMsg": msg,
    "suggestions": sugg,
    "error": error,
    "exception": "",
    "alertStatus": "error",
    "accountName": "",
    "http_status": response.status_code,
    "response_body": response.body
}] {
    response.status_code == 404
    msg = "Test execution API endpoint not found"
    error = "404 Not Found: The requested API endpoint does not exist"
    sugg = "Verify the API URL configuration"
}

deny[{
    "alertMsg": msg,
    "suggestions": sugg,
    "error": error,
    "exception": "",
    "alertStatus": "error",
    "accountName": "",
    "http_status": response.status_code,
    "response_body": response.body
}] {
    response.status_code == 500
    msg = "Test execution API returned server error"
    error = "500 Internal Server Error: API server encountered an error"
    sugg = "Retry the request later or contact API administrator"
}

deny[{
    "alertMsg": msg,
    "suggestions": sugg,
    "error": error,
    "exception": "",
    "alertStatus": "error",
    "accountName": "",
    "http_status": response.status_code,
    "response_body": response.body
}] {
    not response.status_code in [200, 401, 404, 500]
    msg = "Unexpected error occurred while accessing test execution API"
    error = sprintf("Received HTTP status %v", [response.status_code])
    sugg = "Check API connectivity and endpoint configuration"
}

# Process successful response for non-exception cases
deny[{
    "alertMsg": msg,
    "suggestions": sugg,
    "error": "",
    "exception": "",
    "alertStatus": "active",
    "accountName": "",
    "http_status": response.status_code,
    "response_body": response.body
}] {
    response.status_code == 200
    test = response.body[_]
    test.status == "FAIL"
    defects_list = concat(", ", [d.key | d = test.defects[_]; d.key != null])
    msg = sprintf("Test %v failed with defects: %v", [test.key, defects_list])
    sugg = sprintf("Investigate failed test %v and associated defects: %v", [test.key, defects_list])
}
