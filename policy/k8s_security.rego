package main

deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot
    msg = sprintf("Container '%s' must set securityContext.runAsNonRoot: true", [container.name])
}

deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg = sprintf("Container '%s' must set allowPrivilegeEscalation: false", [container.name])
}

deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.resources.limits
    msg = sprintf("Container '%s' must define CPU/memory limits.", [container.name])
}

deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    endswith(container.image, ":latest")
    msg = sprintf("Container '%s' must use an immutable/non-latest image tag.", [container.name])
}
