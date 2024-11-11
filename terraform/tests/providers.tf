terraform {
  required_providers {
    juju = {
      source  = "juju/juju"
      version = "~> 0.14.0"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.4.5"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.3.4"
    }
  }
}