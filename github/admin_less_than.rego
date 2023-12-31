package opsmx

default allow = false

request_components = [input.metadata.rest_url,"repos", input.metadata.github_org, input.metadata.github_repo, "collaborators"]
request_url = concat("/",request_components)

token = input.metadata.github_access_token

request = {
    "method": "GET",
    "url": request_url,
    "headers": {
        "Authorization": sprintf("Bearer %v", [token]),
    },
}

response = http.send(request)

responsesplit = response.body

admins = {user |
    some i
    user = responsesplit[i];
    user.role_name == "admin"
}

admin_users = count(admins)

total = {user |
    some i
    user = responsesplit[i];
    user.type == "User"
}

total_users = count(total)

admin_percentage = admin_users / total_users

deny[msg] {
    admin_percentage > 0.05
    msg := sprintf("More than 5 percentage of total collaborators of %v github repository have admin access", [input.metadata.github_repo])
}
