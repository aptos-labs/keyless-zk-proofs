
This folder contains resources that allow for running an automated test of
a prover service docker image. Specifically, it contains:

- a rust crate that sets up the test and allows for making requests
- a Dockerfile that defines a mock-on-chain and mock-OIDC service that the
  prover service will query
- a Dockerfile that performs the test
- a docker compose file `test_deployment.yml` which orchestrates the
  running of the test.
  
To run the test, **ensure that the image you want to test is tagged
`prover-service`**, and then run in the repo root:

```bash
./scripts/task.sh prover-service test-docker-image <circuit-release>
```
where `<circuit-release>` is one of the releases that the prover service
image supports. 


## The crate

The crate has two functions. First, it allows for setting up the test, by

- generating a training-wheels keypair
- generating a JWK keypair
- converting the circuit release's snarkjs verification key into its
  on-chain represenation, and
- Writing files for the TW VK, JWK json, and on-chain groth16 VK in
  `test-staging`, which the service defined by
  `dockerfiles/mock-on-chain.Dockerfile` will serve via http. This way, the
  service will mock both the on-chain config for the groth16 and TW VKs,
  as well as the OIDC JWK endpoint.
- In addition, it writes out `envvars.env` which the prover service image
  will take as environment variables, which contain the TW private keys and
  the TW and Groth16 VK mocked endpoint URLs.
- Finally, it writes out the JWK private key to a file so that a JWT can be
  signed when generating a test request.

The second function is to actually generate the request and to verify the
response. It does this by generating the "default" request from the prover
service smoke tests. This function is used by `dockerfiles/test-runner.Dockerfile`.


## To test

Ensure docker is installed and dev environment is setup, and then:

```bash
sudo docker build -f prover-service/Dockerfile . --build-arg RELEASE_DEFAULT="test_releases/test-ceremony-20250224" --build-arg "RELEASE_NEW=test_releases/test-ceremony-20250224"
```
you will get an image SHA, call it `<image-id>`
```bash
sudo docker tag <image-id> prover-service
./scripts/task.sh setup download-ceremonies-for-releases "test_releases/test-ceremony-20250224" "test_releases/test-ceremony-20250224"
./scripts/task.sh prover-service test-docker-image "test_releases/test-ceremony-20250224"
```

