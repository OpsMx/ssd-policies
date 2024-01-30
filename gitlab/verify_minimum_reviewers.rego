package play

default number_of_merges = 0
default merges_unreviewed = []
default merges_reviewed_by_bots = []
default merges_reviewed_by_author = []

number_of_merges = count(input)
merges_unreviewed = [input[i].iid | count(input[i].reviewers) == 0]
merges_reviewed_by_bots = [input[i].iid | contains(input[i].reviewers[j].username, "bot")]
merges_reviewed_by_author = [input[i].iid | input[i].reviewers[j].username == input[i].author.username]

deny[{"alertMsg": msg, "error": error, "suggestion": sugg}]{
  count(merges_reviewed_by_bots) > 0
  msg := sprintf("Merge Request with bot user as reviewer found. Merge Request ID: %v.",[merges_reviewed_by_bots])
  sugg := "Adhere to security standards by restricting reviews by bot users."
  error := ""
}

deny[{"alertMsg": msg, "error": error, "suggestion": sugg}]{
  count(merges_reviewed_by_author) > 0
  msg := sprintf("Merge Request with Author as reviewer found. Merge Request ID: %v.",[merges_reviewed_by_author])
  sugg := "Adhere to security standards by restricting reviews by authors."
  error := ""
}

deny[{"alertMsg": msg, "error": error, "suggestion": sugg}]{
  count(merges_unreviewed) > 0
  msg := sprintf("Unreviewed Merge Requests found to be merged. Merge Request ID: %v.",[merges_unreviewed])
  sugg := "Adhere to security standards by restricting merges without reviews."
  error := ""
}
