package opsmx
import future.keywords.in

default approved_artifact_repos = []

approved_artifact_repos = split(input.metadata.ssd_secret.authorized_artifact_repo, ",")
deployed_artifact_source = concat(":",[input.metadata.image, input.metadata.image_tag])

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  count(approved_artifact_repos) == 0
  error := "The essential list of Authorized Artifact Repositories remains unspecified."
  sugg := "Set the AuthorizedArtifactRepos parameter with trusted Artifact Repo to strengthen artifact validation during the deployment process."
  msg := ""
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  not deployed_artifact_source in approved_artifact_repos

  not concat("", ["docker.io/",deployed_artifact_source]) in approved_artifact_repos

  msg := sprintf("The artifact %v:%v has not been sourced from an authorized artifact repo.\nPlease verify the artifacts origin against the following Authorized Artifact Repositories: %v", [input.metadata.image, input.metadata.image_tag, input.metadata.ssd_secret.authorized_artifact_repo])
  sugg := "Ensure the artifact is sourced from an authorized artifact repo."
  error := ""
}
