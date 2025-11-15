terraform {
  required_version = ">= 1.9"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.12"
    }
  }
}

provider "cloudflare" {
  # Reads CLOUDFLARE_API_TOKEN. The token needs Zone.DNS:Edit on one zone.
}
