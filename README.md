# Vault AWS

This tool was created to provide an easy mechanism of updating your local AWS configuration with keys provided from Vault.

VaultAWS will authenticate the user to Vault, asking for AWS keys for the specified Vault Role and if permitted, update the local AWS credential file with keys provided by Vault.

## Usage

VaultAWS will use the environment variable VAULT_ADDR to determine which Vault instance to request keys from.  

### Command Line Options

```
./vaultaws --help

usage: vaultaws --user=USER --password=PASSWORD [<flags>] <command> [<args> ...]

Creates local AWS api keys while authenticating to Vault

Flags:
  -h, --help               Show context-sensitive help (also try --help-long and --help-man).
  -u, --user=USER          Username to authenticate to vault
  -p, --password=PASSWORD  Password for user
      --debug              enable debugging
      --addr=ADDR          Vault Address to authenticate with
  -v, --version            Show application version.

Commands:
  help [<command>...]
    Show help.

  list
    List available roles in Vault

  auth --role=ROLE [<flags>]
    Generate a new authentication key

  renew --profile=PROFILE
    Renew your key lease
```


### Example usage

```
export VAULT_ADDR=https://YOUR_VAULT_URL
./bin/mac/vaultaws auth -u testUser -p testPassword -role readonly -profile test
```

If authentication is successful, an IAM user within the AWS account will be created and keys will be sent back to the enduser.  The keys will then be added to the user's AWS credential file with the profile of test.

AWS CLI can then be run using the --profile test argument to specify using the provided keys.

Vault will automatically clean the IAM user from AWS after the lease has expired, thus making the stored keys unusable.