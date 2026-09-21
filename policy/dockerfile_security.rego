package main

deny contains msg if {
    input[i].Cmd == "user"
    lower(input[i].Value[0]) == "root"
    msg := "Dockerfile must not run as root."
}

has_nonroot_user if {
    input[i].Cmd == "user"
    lower(input[i].Value[0]) != "root"
}

deny contains msg if {
    not has_nonroot_user
    msg := "Dockerfile must set a non-root USER instruction."
}

deny contains msg if {
    input[i].Cmd == "from"
    val := input[i].Value[0]
    endswith(val, ":latest")
    msg := sprintf("Base image '%s' must not use ':latest'. Pin a version.", [val])
}

deny contains msg if {
    input[i].Cmd == "add"
    msg := "Use COPY instead of ADD unless remote fetch or auto-extraction is required."
}

warn contains msg if {
    not has_healthcheck
    msg := "No HEALTHCHECK instruction found - consider adding one."
}

has_healthcheck if {
    input[i].Cmd == "healthcheck"
}
