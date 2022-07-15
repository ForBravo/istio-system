package policy.ingress

allow {
  input.parsed_path[0] == "another"
}