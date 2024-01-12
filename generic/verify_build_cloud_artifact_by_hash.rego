package opsmx


deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
    input.metadata.build_image_sha == "" 
    msg = ""
    sugg = "Ensure that build platform is integrated with SSD."
    error = "Complete Build Artifact information could not be identified."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
    input.metadata.image_sha == ""
    msg = ""
    sugg = "Ensure that deployment platform is integrated with SSD usin Admission Controller."
    error = "Artifact information could not be identified from Deployment Environment."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
    input.metadata.image_sha != input.metadata.build_image_sha
    
    msg = sprintf("Non-identical by hash artifacts identified at Build stage and Deployment Environment.\nBuild Image: %v:%v \n Deployed Image: %v:%v", [input.metadata.build_image, input.metadata.build_image_tag, input.metadata.image, input.metadata.image_tag])
    sugg = "Ensure that built image details & deployed Image details match. Check for possible misconfigurations."
    error = ""
}
