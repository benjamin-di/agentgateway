This deployment branch integrates upstream v1.7.0 with the optional bounded remote
JWKS trust-age change proposed in upstream #4142 and the existing optional strict
JWT timestamp/maximum-lifetime validation. Public source qualification and image
publication retain the existing reproducible release contract. The JWT protocol
fixture covers refresh, expiry and concurrent calls against the actual binary.
Drop each behavioral carry when a compatible upstream release contains it.
