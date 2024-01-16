package opsmx
import future.keywords.in

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  input.metadata.parent_repo != ""
  parent_repo_owner = split(input.metadata.parent_repo, "/")[0]

  parent_repo_owner != input.metadata.owner
  msg := sprintf("The pipeline uses a forked repo from a different organization %s from %s.", [parent_repo_owner, input.metadata.owner])
  sugg := "Refrain from running pipelines originating from forked repos not belonging to the same organization."
  error := ""
}
