# Secure Key Release

This package implements the Secure Key Release operation to release a secret previously imported to Azure Key Vault managed HSM. It interacts with the local attesation library to fetch an MAA token and then uses the MAA token when interacting with the Azure Key Vault managed HSM (mhsm) service for releasing a secret previously imported to the key vault with a user-defined release policy. The MHSM API expects an authentication token that has proper permissions to the MHSM.
