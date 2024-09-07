>[Charmed OpenSearch Tutorial](/t/9722) > 5. Manage passwords
# Manage Passwords

When we accessed OpenSearch earlier in this tutorial, we needed to include a password in the HTTP request. Over time it is a good practice to change the password frequently. Here we will go through setting and changing the password for the admin user.

## Retrieve the admin password
As previously mentioned, the admin credentials (password + the ca chain used to generate the admin client certificate) can be retrieved by running the `get-password` action on the Charmed OpenSearch application:

```bash
juju run opensearch/leader get-password
```
Running the command above should output something like:

```yaml
Running operation 7 with 1 task
  - task 8 on unit-opensearch-0

Waiting for task 8...
ca-chain: |-
  -----BEGIN CERTIFICATE-----
  MIIDPzCCAiegAwIB...
  -----END CERTIFICATE-----
  -----BEGIN CERTIFICATE-----
  MIIDOzCCAiOgAwIB...
  -----END CERTIFICATE-----
password: IbmPfpZthaWMQhxhtm9XyqmSDYGivBpC
username: admin
```
The admin password is under the result: `password`.


## Rotate the admin password

You can change the admin password to a new random and generated password by running:

```shell
juju run opensearch/leader set-password 
```
**Note:** this action can only be run from the leader unit.  
Running the command should output:

```yaml
Running operation 9 with 1 task
  - task 10 on unit-opensearch-0

Waiting for task 10...
admin-password: aW1kMu2pO4GGdw52nfrYHAayu8rn4nn9
```

The admin password is under the result: `admin-password`. It should be different from your previous password.

You can test this password works correctly using the same HTTP requests you used during [Section 5: Connecting to OpenSearch](./5-connecting-to-opensearch.md)

## Set the admin password

You can change the admin password to a specific password by entering:

```shell
juju run opensearch/leader set-password password=<password>
```

Running the command should output:

```yaml
Running operation 11 with 1 task
  - task 12 on unit-opensearch-0

Waiting for task 12...
admin-password: <password>
```

The admin password under the result: `admin-password` should match whatever you passed in when you entered the command.

## Set TLS Private Key

TLS private keys are used for certificate signing requests and should be recycled in the same way as passwords. There are three types of private keys available to be updated on this charm, and they are as follows:

- `"app-admin"` is the key used for requesting a certificate with a CSR for the admin user and cluster administration-related operations.
  - Must only be set on the leader unit.
- `"unit-transport"` is the key used for requesting, for the target unit, a certificate with a CSR for the transport layer (node-to-node communication).
- `"unit-http"` is the key used for requesting, for the target unit, a certificate with a CSR for the HTTP layer. This is used for client-to-node communication.

To change a private key to a random value, run the following command, setting `category` equal to your preferred type of private key:

```shell
juju run opensearch/leader set-tls-private-key category=<category>
```

Running the command should output:

```yaml
Running operation 13 with 1 task
  - task 14 on unit-opensearch-0

Waiting for task 14...

```

No certificate data is presented in the results of this action.

To set the key to a specific value run the following command:

```shell
juju run opensearch/leader set-tls-private-key category=<category> key=<key>
```

Running the command should output:

```yaml
Running operation 15 with 1 task
  - task 16 on unit-opensearch-0

Waiting for task 16...

```

If the key you intend to set has a passphrase, set it like so

```shell
juju run opensearch/leader set-tls-private-key category=<category> password=<password> key=<key>
```

Running the command should output:

```yaml
Running operation 17 with 1 task
  - task 18 on unit-opensearch-0

Waiting for task 18...

```


>**Next step**: [6. Scale horizontally](/t/9720)