package policy.ingress

import future.keywords
# Add policy/rules to allow or deny ingress traffic

default allow = false


jwks := json.marshal(data.jwks.jwks)

bearer_token := t {
	# Bearer tokens are contained inside of the HTTP Authorization header. This rule
	# parses the header and extracts the Bearer token value. If no Bearer token is
	# provided, the `bearer_token` value is undefined.
	v := input.attributes.request.http.headers.authorization
	startswith(v, "Bearer ")
	t := substring(v, count("Bearer "), -1)
}

status_code := 401 {
  bearer_token
  not claims
}

headers[k] = v {
    claims
	k := "x-mkt-claims"
	v := json.marshal(claims)
}

claims := payload {
	# Verify the signature on the Bearer token. In this example the secret is
	# hardcoded into the policy however it could also be loaded via data or
	# an environment variable. Environment variables can be accessed using
	# the `opa.runtime()` built-in function.
	io.jwt.verify_rs256(bearer_token, jwks)

	# This statement invokes the built-in function `io.jwt.decode` passing the
	# parsed bearer_token as a parameter. The `io.jwt.decode` function returns an
	# array:
	#
	#	[header, payload, signature]
	#
	# In Rego, you can pattern match values using the `=` and `:=` operators. This
	# example pattern matches on the result to obtain the JWT payload.
	[_, payload, _] := io.jwt.decode(bearer_token)
}

allow {
  input.parsed_path[0] == "public"
}

allow {
  input.parsed_path[0] == "private1"
  claims.aud == "https://nigel-test-rba.us.auth0.com/api/v2/"
}

allow {
  input.parsed_path[0] == "private2"
  claims.aud == "https://nigel-test-rba.us.auth0.com/api/v2/1"
}

allow {
	input.parsed_path[0] == "health"
}
