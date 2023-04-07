# Manage Passwords

## Passwords

When we accessed OpenSearch earlier in this tutorial, we needed to include a password in the HTTP request. Over time it is a good practice to change the password frequently. Here we will go through setting and changing the password for the admin user.

### Retrieve the admin password
As previously mentioned, the admin credentials (password + the ca chain used to generate the admin client certificate) can be retrieved by running the `get-password` action on the Charmed OpenSearch application:

```bash
juju run-action opensearch/leader get-password --wait
```
Running the command should output:

```yaml
unit-opensearch-0:
  UnitId: opensearch/0
  id: "2"
  results:
    ca-chain: |-
      <certificate>
    password: <password>
    username: admin
  status: completed
  timing:
    completed: 2023-04-06 11:36:41 +0000 UTC
    enqueued: 2023-04-06 11:36:20 +0000 UTC
    started: 2023-04-06 11:36:36 +0000 UTC
```
The admin password is under the result: `admin-password`.


### Rotate the admin password

You can change the admin password to a new random and generated password by running:

```shell
juju run-action opensearch/leader set-password --wait
```
**Note:** this action can only be run from the leader unit.  
Running the command should output:

```yaml
unit-opensearch-0:
  UnitId: opensearch/0
  id: "8"
  results:
    admin-password: n4E4z3Dk19irKJPeZU27B24l1wKoA2sP
  status: completed
  timing:
    completed: 2023-04-06 11:38:22 +0000 UTC
    enqueued: 2023-04-06 11:38:17 +0000 UTC
    started: 2023-04-06 11:38:20 +0000 UTC
```

The admin password is under the result: `admin-password`. It should be different from your previous password.

You can test this password works correctly using the same HTTP requests you used during [Section 5: Connecting to OpenSearch](./5-connecting-to-opensearch.md)

### Set the admin password

You can change the admin password to a specific password by entering:

```shell
juju run-action opensearch/leader set-password password=<password> --wait
```

Running the command should output:

```yaml
unit-opensearch-0:
  UnitId: opensearch/0
  id: "12"
  results:
    admin-password: <password>
  status: completed
  timing:
    completed: 2023-04-06 11:39:41 +0000 UTC
    enqueued: 2023-04-06 11:39:38 +0000 UTC
    started: 2023-04-06 11:39:40 +0000 UTC
```

The admin password under the result: `admin-password` should match whatever you passed in when you entered the command.

### Set TLS Private Key

TLS private keys are used for certificate signing requests, and should be recycled in the same way as passwords. There are three types of private keys available to be updated on this charm, and they are as follows:

- `"app-admin"` is the key used for requesting a certificate with a CSR for the admin user and cluster administration related operations.
  - Must only be set on the leader unit.
- `"unit-transport"` is the key used for requesting, for the target unit, a certificate with a CSR for the transport layer (node to node communication).
- `"unit-http"` is the key used for requesting, for the target unit, a certificate with a CSR for the admin user and cluster administration related operations.

To change a private key to a random value, run the following command, setting `category` equal to your preferred type of private key:

```shell
juju run-action opensearch/leader set-tls-private-key category=<category> --wait
```

Running the command should output:

```yaml
unit-opensearch-0:
  UnitId: opensearch/0
  id: "14"
  results: {}
  status: completed
  timing:
    completed: 2023-04-06 11:45:32 +0000 UTC
    enqueued: 2023-04-06 11:45:29 +0000 UTC
    started: 2023-04-06 11:45:30 +0000 UTC
```

No certificate data is presented in the results of this action.

To set the key to a specific value run the following command:

```shell
juju run-action opensearch/leader set-tls-private-key category=<category> key=<key> --wait
```

Running the command should output:

```yaml
unit-opensearch-0:
  UnitId: opensearch/0
  id: "16"
  results: {}
  status: completed
  timing:
    completed: 2023-04-06 12:07:02 +0000 UTC
    enqueued: 2023-04-06 12:07:01 +0000 UTC
    started: 2023-04-06 12:07:01 +0000 UTC
```

If the key you intend to set has a passphrase, set it like so

```shell
juju run-action opensearch/leader set-tls-private-key category=<category> password=<password> key=<key> --wait
```

Running the command should output:

```yaml
unit-opensearch-0:
  UnitId: opensearch/0
  id: "16"
  results: {}
  status: completed
  timing:
    completed: 2023-04-06 12:37:55 +0000 UTC
    enqueued: 2023-04-06 12:37:52 +0000 UTC
    started: 2023-04-06 12:37:54 +0000 UTC
```

---

## Next Steps

The next stage in this tutorial is about horizontally scaling the OpenSearch cluster, and can be found [here](./t-horizontal-scaling.md).
