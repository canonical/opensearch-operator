# operator-template

## Description
OpenSearch Machine Charm

## Usage

```
cat <<EOF > cloudinit-userdata.yaml
cloudinit-userdata: |
  postruncmd:
    - [ "sysctl", "-w", "vm.swappiness=0" ]
    - [ "sysctl", "-w", "vm.max_map_count=262144" ]
    - [ "sysctl", "-w", "net.ipv4.tcp_retries2=5" ]
EOF

juju model-config ./cloudinit-userdata.yaml
```

TODO: Provide high-level usage, such as required config or relations

## Relations

TODO: Provide any relations which are provided or required by your charm

## OCI Images

TODO: Include a link to the default image your charm uses

## Contributing

<!-- TEMPLATE-TODO: Change this URL to be the full Github path to CONTRIBUTING.md-->

Please see the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines on enhancements to this
charm following best practice guidelines, and
[CONTRIBUTING.md](https://github.com/<name>/<operator>/blob/main/CONTRIBUTING.md) for developer
guidance.
