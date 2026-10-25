This deployment branch starts at upstream v1.6.0. The only behavior change is the
optional maximum age of successfully fetched remote JWT signing keys, developed
on the fork's jwt-jwks-max-age branch. It must have an open upstream pull request
before deployment. Drop the backport when adopting an upstream release containing
that change. The additional fleet workflow uses GitHub-hosted runners and upstream's
Dockerfile; it adds no gateway behavior.
