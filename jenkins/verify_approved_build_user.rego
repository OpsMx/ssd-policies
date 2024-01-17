package opsmx
import future.keywords.in
default approved_servers_count = 0
default list_approved_user_str = []

build_url = split(input.metadata.build_url, "/")[2]
list_approved_user_str = {input.metadata.ssd_secret.build_access_config.credentials[i].approved_user | split(input.metadata.ssd_secret.build_access_config.credentials[i].url, "/")[2] == build_url}
list_approved_users = split(list_approved_user_str[_], ",")

deny[{"alertMsg": msg, "suggestion": sugg, "error": error }] {
  approved_servers_count = count(input.metadata.ssd_secret.build_access_config.credentials)
  approved_servers_count == 0
  msg:=""
  sugg:="Set the BuildAccessConfig.Credentials parameter with trusted build server URLs to strengthen artifact validation during the deployment process."
  error:="The essential list of approved build URLs remains unspecified."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error }]{
  count(input.metadata.ssd_secret.build_access_config.credentials) > 0
  list_approved_user_str == []
  msg := ""
  sugg := "Set the BuildAccessConfig.Credentials parameter with trusted build server URLs and users to strengthen artifact validation during the deployment process."
  error := "The essential list of approved build users remains unspecified."
}
  
deny[{"alertMsg": msg, "suggestion": sugg, "error": error }]{
  count(input.metadata.ssd_secret.build_access_config.credentials) > 0
  not input.metadata.build_user in list_approved_users
  msg:="The artifact has not been sourced from an approved user.\nPlease verify the artifacts origin."
  sugg:="Ensure the artifact is sourced from an approved user."
  error:=""
}
