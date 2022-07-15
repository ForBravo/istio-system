package policy.ingress

# Add policy/rules to allow or deny ingress traffic

default allow = false

jwks_request(url) = http.send({
    "url": url,
    "method": "GET",
    "force_cache": true,
    "force_cache_duration_seconds": 3600 # Cache response for an hour
})

jwks := jwks_request("https://nigel-test-rba.us.auth0.com/.well-known/jwks.json").raw_body

# jwks :=`{
#     "keys": [
#         {
#             "alg": "RS256",
#             "kty": "RSA",
#             "use": "sig",
#             "n": "9b5fWejQWYjtUl_OCtsorhMWyYjJCWnseNK61QeRkNWIoTT-_5kWfQGmFwmYIqIMz4uSAFBEFXBxQEDsysmsJZwbkYMBOXpHJFnMGnyJtFsgbHDeqotCWhrBvZuI9lDHZs1V3QM0ws0u-iZ1k78ueHkN_MeJsE2b6AJAAeofgt448VfDX9_LGpObDsolOUa_vrfjXUDIm5RtjBb0sjQtO9ii9To0_mZ2E3yoRWc06p0SVTt2sSvtfh4VkFeaRZb1VeHA1zM5hOJ-nci4YcsgSR4CdWY5ufirG6jUueVGwVqCX62UY5RR-ZbXRW9mOvur1J-E0aPNYgQpNNiYIa5Ntw",
#             "e": "AQAB",
#             "kid": "gYyKQLkGV0fPKGH8JIMT5",
#             "x5t": "FdQ0L7W9agQMsyiXjCD547a1RoQ",
#             "x5c": [
#                 "MIIDETCCAfmgAwIBAgIJFRZvlKEAD2T8MA0GCSqGSIb3DQEBCwUAMCYxJDAiBgNVBAMTG25pZ2VsLXRlc3QtcmJhLnVzLmF1dGgwLmNvbTAeFw0yMjA2MzAwODQ2MjNaFw0zNjAzMDgwODQ2MjNaMCYxJDAiBgNVBAMTG25pZ2VsLXRlc3QtcmJhLnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPW+X1no0FmI7VJfzgrbKK4TFsmIyQlp7HjSutUHkZDViKE0/v+ZFn0BphcJmCKiDM+LkgBQRBVwcUBA7MrJrCWcG5GDATl6RyRZzBp8ibRbIGxw3qqLQloawb2biPZQx2bNVd0DNMLNLvomdZO/Lnh5DfzHibBNm+gCQAHqH4LeOPFXw1/fyxqTmw7KJTlGv763411AyJuUbYwW9LI0LTvYovU6NP5mdhN8qEVnNOqdElU7drEr7X4eFZBXmkWW9VXhwNczOYTifp3IuGHLIEkeAnVmObn4qxuo1LnlRsFagl+tlGOUUfmW10VvZjr7q9SfhNGjzWIEKTTYmCGuTbcCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU6OTwfOttgaqBn0cs4WaIzqrZM1AwDgYDVR0PAQH/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQAiZ10qnMEJlklJmYVPzvGeP3IRITvAmfMX6zrHqqnQ1+5MSYISQPUcHadRwUwYER9P7v5zlGwLWTkHU5ijjJfMz3eK2gZ6ywOVV/ZS3FMCbMYQ6DuIH2vL8QCzF7oke7Pm6aChLMJCkLwzoie0S5jv0LpwaCWu5G4wipbB8Asv4c+HhMjbD5U5TG2twqi3aeAugKGrFNI1KZch279NZpUyCyV7scnaTSNDb01wgqJV0vrENtiH7V4LZINJaJi5CRKdXG5P42/XRuxfiL/hSX0FDSssJabEBYe4uLjmiHn9lAwJU42jo3cEkXNEGlWu5l+BR+6vg3mecYKKU/TnfAcA"
#             ]
#         },
#         {
#             "alg": "RS256",
#             "kty": "RSA",
#             "use": "sig",
#             "n": "zBUvdRZH8EltrDk0SF0kVxUgPwnsfDUVq7AAFJQ9EGmP2BH5FqIWd5CI5s1jcEiQ0Op2EI7qClCVnP-IvRLMW5aH03dVDLPA6WGH_9TejxjrqKSqGWyrZpt0ncr12spSB51esd0u0goB34U6zCGJzOAXWu4VBaW-wUNE6yNE8zhHuo2Fk7r2H1aSaI8knlisz8__njB7CrKNtypC78GLqeSb3HEnkIgQBCj2Ip4zQ4iW0iF8lVrvPyxNkmfHRfW47Th1mPawHJVR2dQkc4sm1H7HvPYdszdROYMVYGZVHdCjLnNnYL0BvDIac1pKUmfF0QgklFgWiu9oBFCKGgzfpQ",
#             "e": "AQAB",
#             "kid": "4V1ugQknxrkAyo--fh98q",
#             "x5t": "f7EPlMNTiypl4_3yYcUdkOx1m2w",
#             "x5c": [
#                 "MIIDETCCAfmgAwIBAgIJB8rab3bQG8ZBMA0GCSqGSIb3DQEBCwUAMCYxJDAiBgNVBAMTG25pZ2VsLXRlc3QtcmJhLnVzLmF1dGgwLmNvbTAeFw0yMjA2MzAwODQ2MjNaFw0zNjAzMDgwODQ2MjNaMCYxJDAiBgNVBAMTG25pZ2VsLXRlc3QtcmJhLnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMwVL3UWR/BJbaw5NEhdJFcVID8J7Hw1FauwABSUPRBpj9gR+RaiFneQiObNY3BIkNDqdhCO6gpQlZz/iL0SzFuWh9N3VQyzwOlhh//U3o8Y66ikqhlsq2abdJ3K9drKUgedXrHdLtIKAd+FOswhiczgF1ruFQWlvsFDROsjRPM4R7qNhZO69h9WkmiPJJ5YrM/P/54wewqyjbcqQu/Bi6nkm9xxJ5CIEAQo9iKeM0OIltIhfJVa7z8sTZJnx0X1uO04dZj2sByVUdnUJHOLJtR+x7z2HbM3UTmDFWBmVR3Qoy5zZ2C9AbwyGnNaSlJnxdEIJJRYForvaARQihoM36UCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU5J4a1nsBiNIaYdJ6Go2OGpqFomAwDgYDVR0PAQH/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQBMNgsoOzgb5+wf0CiG5D1D7Qs1FsyPmH7rblyKj2UPVRHfqzpuJmfYFRbC4XImDMXQ/UXCMgwO4gfeBKd+MZvFMGwoKOb4QKYTpNZFuqk2pt0vc/OTfnm+sQP2fM6IjI/LKG3fg7zYMOg03FDtHgwPJCes5T/vAjz7pmu/0GcoIeQVXfeNsWaYsNngV3gfUQauDQT4sYkYPqK4VApatS3lBpSgnlqKJoR56BOY9QmuQyHLU30qlc0AcN4FPaDrDv5hzTZ0t6UgCPuksMPGLv92+d1kJBRB+5Na8/rT3KoYcx4Wa7uCCxEYaOE0GvHWq+/6+udXHM/G9NaIJSmjt/w+"
#             ]
#         }
#     ]
# }`

bearer_token := t {
	# Bearer tokens are contained inside of the HTTP Authorization header. This rule
	# parses the header and extracts the Bearer token value. If no Bearer token is
	# provided, the `bearer_token` value is undefined.
	v := input.attributes.request.http.headers.authorization
	startswith(v, "Bearer ")
	t := substring(v, count("Bearer "), -1)
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
