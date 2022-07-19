package policy.ingress

import future.keywords

allow {
  input.parsed_path[0] == "another"
}