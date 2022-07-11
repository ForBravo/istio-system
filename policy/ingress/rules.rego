package policy.ingress

# Add policy/rules to allow or deny ingress traffic

default allow = false

jwks := data.jwks.jwks.keys

allow {
  input.parsed_path[0] == "asd"
}

allow {
  input.parsed_path[0] == "user"
  io.jwt.verify_rs256(input.request.http.headers.authorization,jwks)
}

allow {
	input.parsed_path[0] == "health"
}
