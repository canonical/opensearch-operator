# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

terraform {
  required_version = ">= 1.11"

  required_providers {
    juju = {
      source  = "juju/juju"
      version = "~> 2.2"
    }
  }
}
