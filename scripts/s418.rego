package opsmx
import future.keywords.in

default allow = false

request = {
    "method": "GET",
    "url": "https://xrayjira.free.beeceptor.com/api/testexec/TEST-123/test?detailed=true"
}

response = http.send(request)

# Handle HTTP errors
deny[msg] {
    response.status_code == 401
    msg = "Unauthorized to access test execution API"
    error = "401 Unauthorized: Invalid credentials or permissions"
    sugg = "Check API authentication credentials and permissions"
}

deny[msg] {
    response.status_code == 404
    msg = "Test execution API endpoint not found"
    error = "404 Not Found: The requested API endpoint does not exist"
    sugg = "Verify the API URL configuration"
}

deny[msg] {
    response.status_code == 500
    msg = "Test execution API returned server error"
    error = "500 Internal Server Error: API server encountered an error"
    sugg = "Retry the request later or contact API administrator"
}

deny[msg] {
    not response.status_code in [200, 401, 404, 500]
    msg = "Unexpected error occurred while accessing test execution API"
    error = sprintf("Received HTTP status %v", [response.status_code])
    sugg = "Check API connectivity and endpoint configuration"
}

# Process successful response: collect all failing-test messages and join into one string separated by newlines
deny[msg] {
    response.status_code == 200

    # build an array of per-test messages for tests that failed
    failures := [
        sprintf("Test %v failed with defects: %v", [
            t.key,
            concat(", ", [d.key | d := t.defects[_]; d.key != null])
        ]) |
        t := response.body[_];
        t.status == "FAIL"
    ]

    # only deny if there is at least one failure
    count(failures) > 0

    # join into a single string separated by newline characters
    msg = concat("\n", failures)

    # optional short suggestion (single string); can be adjusted if you want per-test suggestions instead
    sugg = "Investigate failed tests and associated defects; see details in the message."
}
