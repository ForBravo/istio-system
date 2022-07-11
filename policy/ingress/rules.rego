package policy.ingress

# Add policy/rules to allow or deny ingress traffic

default allow = false

allow {
  input.parsed_path[0] == "asd"
}

allow {
	input.parsed_path[0] == "health"
}
