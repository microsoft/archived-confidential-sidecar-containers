# Confidential Sidecar Containers
This repository contains the code needed to build the sidecar containers used for [confidential containers.](https://techcommunity.microsoft.com/t5/azure-confidential-computing/microsoft-introduces-preview-of-confidential-containers-on-azure/ba-p/3410394)

The code in this repository should be located at ``$GOPATH/src/microsoft/confidential-sidecar-containers``.

## Secure key release (SKR) sidecar
The ``docker/skr/build.sh`` script builds all necessary Go tools for secure key release as standalone binaries and creates a Docker image that contains them so that it 
can be used as a sidecar container. The skr sidecar container is executed by calling the script ``skr.sh``.

The skr sidecar can be queried by application containers hosted in the same pod (or container group) for retrieving attestation reports and for releasing secrets from managed HSM key vaults.

The ``examples/skr`` shows an example of how the skr sidecar can be deployed and tested within a confidential container group on ACI.

### Third-party code 
We modified the [AES unwrap key without padding method](https://github.com/NickBall/go-aes-key-wrap/blob/master/keywrap.go) to implement the aes key unwrap with padding method.

## Encrypted filesystem sidecar
The ``docker/encfs/build.sh`` script builds all necessary Go tools (for encrypted filesystems) and creates a Docker image that contains them so that it can be used as a sidecar container. The encrypted filesystem sidecar container is executed by calling the script ``encfs.sh`` with a base64-encoded string or as an environment variable.

The encrypted filesystem sidecar uses the SKR library to release key material from managed HSM key vaults required for mounting the encrypted filesystems required by the application.

The ``examples/encfs`` shows an example of how the encrypted filesystem sidecar can be deployed within a confidential container group on ACI.
## Dependencies:
- Golang 1.16 or later
- Docker
- GCC 9.4.0 or later

# Contributing
This project welcomes contributions and suggestions. Most contributions require you to
agree to a Contributor License Agreement (CLA) declaring that you have the right to,
and actually do, grant us the rights to use your contribution. For details, visit
https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need
to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the
instructions provided by the bot. You will only need to do this once across all repositories using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/)
or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

# Trademarks
This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow Microsoft’s Trademark & Brand Guidelines. Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party’s policies.
