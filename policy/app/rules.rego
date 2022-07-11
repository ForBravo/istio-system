package policy.app

# Add application policy/rules to allow or deny traffic (ex. HTTP)

default allow= false

allow {
  input.attributes.request.http.method == "GET"
  input.parsed_path[0] == "asd"
}


