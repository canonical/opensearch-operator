---
relatedlinks: "[GitHub](https://github.com/canonical/opensearch-operator), [Charmhub](https://charmhub.io/opensearch), [Charmhub&#32;(K8s)](https://charmhub.io/opensearch-k8s)"
myst:
  html_meta:
    description: "How to contribute to Charmed OpenSearch - report issues, contribute code and documentation, get in touch with the team, and learn about Canonical career opportunities."
---

(contributing-guide)=
# How to contribute

Charmed OpenSearch is an open-source project developed and supported by
[Canonical](https://canonical.com/) that welcomes community contributions,
suggestions, fixes, and constructive feedback.

If you would like to contribute a larger change, please [get in touch](contributing-contact)
with us first so we can help you shape the contribution.

## Report an issue

Report bugs and feature requests on
[GitHub](https://github.com/canonical/opensearch-operator/issues/new). For
documentation issues, use the **Give feedback** button at the top of the
relevant page to open a pre-filled GitHub issue.

```{note}
Please do **not** use GitHub issues for security topics. See
[the section below](contributing-security).
```

(contributing-security)=
### Report a security issue

Security issues should be reported through
[Launchpad](https://wiki.ubuntu.com/DebuggingSecurity#How_to_File), following
the Ubuntu security disclosure process. Please do **not** file GitHub issues
on security topics.

See also [SECURITY.md](https://github.com/canonical/opensearch-operator/blob/2/edge/SECURITY.md)
in the repository.

(contributing-contact)=
## Get in touch

If you have questions after reading this documentation or would like to discuss
Charmed OpenSearch, get in touch through one of the following channels:

* Chat with the Data team directly on
  [Matrix](https://matrix.to/#/#charmhub-data-platform:ubuntu.com).
* Ask questions and share feedback on the
  [Discourse forum](https://discourse.charmhub.io/t/charmed-opensearch-documentation/9729).
* To talk to Canonical about your use case or commercial support, use the
  [business form](https://canonical.com/data/opensearch#get-in-touch).

(contributing-code)=
## Contribute code

If you would like to contribute, the following sections
cover the building and testing for both source code and documentation.

### Requirements

To build the charm locally, you will need to install
[Charmcraft](https://snapcraft.io/charmcraft) (or [charmcraftcache](https://github.com/canonical/charmcraftcache)),
as well as [`tox`](https://tox.wiki/) and [Poetry](https://python-poetry.org/).
The easiest way to install the last two is with [pipx](https://pipx.pypa.io/stable/):

```bash
pipx install tox
pipx install poetry
pipx install charmcraftcache
```

To run the charm locally with Juju, it is recommended to use
[LXD](https://linuxcontainers.org/lxd/introduction/) as your virtual machine
manager. Instructions for running Juju on LXD can be found
[here](https://documentation.ubuntu.com/juju/3.6/reference/cloud/list-of-supported-clouds/lxd/).

This repository is a monorepo containing two charms:

* `machine/` — the machine charm (`opensearch`), which installs and manages
  OpenSearch from the [OpenSearch snap](https://snapcraft.io/opensearch) on
  VMs and machine clusters.
* `kubernetes/` — the Kubernetes charm (`opensearch-k8s`), which deploys and
  manages OpenSearch as a container workload on Kubernetes.

Each charm is a self-contained project: build commands must be run from
inside the corresponding directory.

### Host and model prerequisites

OpenSearch has a set of
[system requirements](https://opensearch.org/docs/latest/install-and-configure/install-opensearch/index/)
to function correctly. Some of those settings must be set using
`cloudinit-userdata` on the model, while others must be set on the host machine:

```bash
cat <<EOF > cloudinit-userdata.yaml
cloudinit-userdata: |
  postruncmd:
    - [ 'echo', 'vm.max_map_count=262144', '>>', '/etc/sysctl.conf' ]
    - [ 'echo', 'vm.swappiness=0', '>>', '/etc/sysctl.conf' ]
    - [ 'echo', 'net.ipv4.tcp_retries2=5', '>>', '/etc/sysctl.conf' ]
    - [ 'echo', 'fs.file-max=1048576', '>>', '/etc/sysctl.conf' ]
    - [ 'sysctl', '-p' ]
EOF

echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
echo "vm.swappiness=0" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

Then create a new model and set the previously generated file in it:

```bash
# Create a model
juju add-model dev

# Enable DEBUG logging
juju model-config logging-config="<root>=INFO;unit=DEBUG"

# Add cloudinit-userdata
juju model-config --file=./cloudinit-userdata.yaml

# Increase the frequency of the update-status event
juju model-config update-status-hook-interval=1m
```

### Build and deploy

To build a charm, enter the corresponding directory and pack it:

```bash
# Clone and enter the repository
git clone https://github.com/canonical/opensearch-operator.git
cd opensearch-operator/machine   # or: cd opensearch-operator/kubernetes

# Build the charm locally
charmcraftcache pack
```

You can then deploy the charm with a TLS relation:

```bash
# Deploy the self-signed-certificates operator
juju deploy self-signed-certificates --channel=latest/stable --show-log --verbose

# Generate a CA certificate
juju config \
    self-signed-certificates \
    ca-common-name="CN_CA" \
    certificate-validity=365 \
    root-ca-validity=365

# Deploy the opensearch charm
juju deploy -n 1 ./opensearch_ubuntu-22.04-amd64.charm --series jammy --show-log --verbose

# Relate the opensearch charm with the self-signed-certificates operator
juju integrate self-signed-certificates opensearch
```

```{note}
The TLS settings shown here are for self-signed-certificates, which are not
recommended for production clusters. The TLS Certificates Operator offers a
variety of configurations. Read more on the self-signed-certificates Operator
[here](https://charmhub.io/self-signed-certificates).
```

### Develop and test

You can create an environment for development with Poetry:

```bash
poetry install
```

Run the test suites with:

```bash
tox run -e format        # update your code according to linting rules
tox run -e lint          # code style
tox run -e unit          # unit tests
tox run -e integration   # integration tests
tox                      # runs 'format', 'lint', and 'unit' environments
```

Integration tests can also be run with [Charmcraft](https://snapcraft.io/charmcraft)
and [Spread](https://github.com/canonical/spread) on an LXD VM backend:

```bash
charmcraft test lxd-vm:
```

The tutorial end-to-end test suite (requires
[Multipass](https://documentation.ubuntu.com/multipass/) and
[Spread](https://github.com/canonical/spread)) can be run with:

```bash
tox -e tutorial           # extract scripts + run Spread tests
tox -e tutorial-extract   # generate test scripts only
```

See [tests/tutorial/](https://github.com/canonical/opensearch-operator/tree/2/edge/tests/tutorial)
for the extraction scripts and the generated tasks.

```{note}
The code blocks in the documentation tutorial pages are extracted and run as
part of the tutorial test suite. When editing `docs/tutorial/*.md`, make sure
`tox -e tutorial-extract` still succeeds.
```

### Review process

All enhancements require review before being merged. Code review typically
examines code quality, test coverage, and the user experience for Juju
administrators of this charm.

Please help us out in ensuring easy-to-review branches by rebasing your pull
request branch onto the `main` branch. This also avoids merge commits and
creates a linear Git commit history.

Familiarising yourself with the
[Ops framework](https://canonical.com/juju/docs/ops/latest/) will help you when
working on new features or bug fixes.

(contributing-docs)=
## Contribute documentation

The documentation lives in the `docs/` folder of this repository and is built
with [Sphinx](https://www.sphinx-doc.org/) from MyST Markdown sources. It is
published on [canonical.com](https://canonical.com/data/opensearch/docs/).

### Prerequisites

* A [GitHub account](https://docs.github.com/en/get-started/start-your-journey/creating-an-account-on-github).
* Compliance with the [Code of Conduct](contributing-code-of-conduct).

### Report a documentation issue

To report an issue with spelling, grammar, or technical content,
[file an issue on GitHub](https://github.com/canonical/opensearch-operator/issues/new)
or use the **Give feedback** button at the top of the affected page.

### Make a contribution

For a quick fix — a typo, a broken link, a small clarification — the easiest
way is to click the pencil icon at the top of the documentation page (next to
the **Give feedback** button). It takes you to the GitHub web editor for that
page, where you can submit a pull request directly through the web interface.

For larger contributions:

1. Create a branch (in the main repository or in a fork) from the current
   `main` and modify the documentation files as necessary.
2. Raise a pull request against `main` to start the review process.
3. Once the pull request is approved and all comments are addressed, it can
   be merged.

To preview and test the documentation locally:

```bash
cd docs
make run        # live-reload build served on http://127.0.0.1:8000
```

Before submitting, make sure the following checks pass:

```bash
cd docs
make html       # full build; fails on warnings
make linkcheck  # verify all external links
make lint-md    # Markdown linting
make spelling   # Vale spelling check
make woke       # inclusive-language check
```

```{note}
The documentation for OpenSearch Dashboards lives in the
[`opensearch-dashboards-operator`](https://github.com/canonical/opensearch-dashboards-operator)
repository and is included here as a git submodule. Contribute Dashboards
documentation changes upstream, in that repository.
```

The documentation follows the [Diátaxis structure](https://diataxis.fr/):
tutorials, how-to guides, reference, and explanation each live in their own
section and should not be mixed.

## Code of conduct

(contributing-code-of-conduct)=
This project follows the
[Ubuntu Code of Conduct](https://ubuntu.com/community/code-of-conduct).
Maintainers reserve the right to remove any contributions that do not respect
it.

## Contributor agreement

Canonical welcomes contributions to Charmed OpenSearch. Please check out our
[contributor agreement](https://ubuntu.com/legal/contributors) if you're
interested in contributing to the solution.

## We are hiring!

Also, if you truly enjoy working on open-source projects like this one, check
out the [career options](https://canonical.com/careers/all) we have at
[Canonical](https://canonical.com/).

## Useful links

* [Canonical Data solutions](https://canonical.com/data)
* [Charmed OpenSearch](https://charmhub.io/opensearch)
* [Charmed OpenSearch on Kubernetes](https://charmhub.io/opensearch-k8s)
* [Git sources for Charmed OpenSearch](https://github.com/canonical/opensearch-operator)
* [Canonical Data on Launchpad](https://launchpad.net/~data-platform)
* [Canonical Data on Matrix](https://matrix.to/#/#charmhub-data-platform:ubuntu.com)
