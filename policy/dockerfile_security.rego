package main

deny[msg] {
    input[i].Cmd == "user"
    lower(input[i].Value[0]) == "root"
    msg = "Dockerfile must not run as root."
}

deny[msg] {
    not has_nonroot_user
    msg = "Dockerfile must set a non-root USER instruction."
}

has_nonroot_user {
    input[i].Cmd == "user"
    lower(input[i].Value[0]) != "root"
}

deny[msg] {
    input[i].Cmd == "from"
    val := input[i].Value[0]
    endswith(val, ":latest")
    msg = sprintf("Base image '%s' must not use ':latest'. Pin a version.", [val])
}

deny[msg] {
    input[i].Cmd == "add"
    msg = "Use COPY instead of ADD unless remote fetch or auto-extraction is required."
}

warn[msg] {
    not has_healthcheck
    msg = "No HEALTHCHECK instruction found - consider adding one."
}

has_healthcheck {
    input[i].Cmd == "healthcheck"
}
