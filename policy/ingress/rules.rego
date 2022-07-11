package policy.ingress

# Add policy/rules to allow or deny ingress traffic

default allow = false

allow {
  input.attributes.request.http.method == "GET"
  input.parsed_path[0] == "asd"
}
