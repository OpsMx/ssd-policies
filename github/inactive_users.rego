package opsmx
token = input.metadata.github_access_token
request_components = [input.metadata.rest_url,"repos", input.metadata.github_org, input.metadata.github_repo, "activity?time_period=quarter&activity_type=push&per_page=500"]

collaborators_components = [input.metadata.rest_url,"repos", input.metadata.github_org, input.metadata.github_repo, "collaborators"]
collaborators_url = concat("/",collaborators_components)

collaborators = {
    "method": "GET",
    "url": collaborators_url,
    "headers": {
        "Authorization": sprintf("Bearer %v", [token]),
    },
}

coll_resp = http.send(collaborators)

responsesplit = coll_resp.body

coll_users = {coluser |
    some i
    coluser = responsesplit[i];
    coluser.role_name != "admin"
    coluser.type == "User"
}

request_url = concat("/",request_components)

request = {
    "method": "GET",
    "url": request_url,
    "headers": {
        "Authorization": sprintf("Bearer %v", [token]),
    },
}
resp = http.send(request)
link_1 = split(resp.headers.link[0], " ")[0]
decoded_link_1 = replace(link_1, "\u003e;", "")
decoded_link_2 = replace(decoded_link_1, "\u003c", "")
link_request = {
    "method": "GET",
    "url": decoded_link_2,
    "headers": {
        "Authorization": sprintf("Bearer %v", [token]),
    },
}
resp2 =  http.send(link_request)

evnt_users = resp.body

evnt_logins = {user |
    some i
    user = evnt_users[i];
    user.actor.type == "User"
}

login_values[login] {
    user = evnt_logins[_]
    login = user.actor.login
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  allusers = coll_users[_]
  eventlogins = evnt_logins[_]
  allusers.login == login_values[_]
  msg := sprintf("Access of Github repository %s has been granted to users %v who have no activity from last three months", [input.metadata.github_repo,login_values[_]])
  sugg := "Adhere to the company policy and revoke access of inactive members"
  error := ""
}
