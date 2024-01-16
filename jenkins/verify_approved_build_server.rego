package opsmx
import future.keywords.in
default approved_servers_count = 0

deny[{"alertMsg": msg, "suggestion": sugg, "error": error }] {
  approved_servers_count = count(input.metadata.ssd_secret.build_access_config.credentials)
  approved_servers_count == 0
  msg:=""
  sugg:="Set the BuildAccessConfig.Credentials parameter with trusted build server URLs to strengthen artifact validation during the deployment process."
  error:="The essential list of approved build URLs remains unspecified"
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error }]{
  count(input.metadata.ssd_secret.build_access_config.credentials) > 0
  build_url = split(input.metadata.build_url, "/")[2]
  list_of_approved_servers = [split(input.metadata.ssd_secret.build_access_config.credentials[i].url, "/")[2] |input.metadata.ssd_secret.build_access_config.credentials[i].url != ""]

  not build_url in list_of_approved_servers
  msg:=sprintf("The artifact has not been sourced from an approved build server.\nPlease verify the artifacts origin against the following approved build URLs: %v", [concat(",", list_of_approved_servers)])
  sugg:="Ensure the artifact is sourced from an approved build server."
  error:=""
}
