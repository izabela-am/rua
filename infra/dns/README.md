# infra/dns

The DNS records Rua depends on, for one Cloudflare zone. Render and Supabase are configured by hand.

```sh
export CLOUDFLARE_API_TOKEN=...   # Zone.DNS:Edit on the zone
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform plan
```

State is local by default. `terraform.tfvars` and state files are git-ignored.

Order on a fresh setup: apply without `rua_self`, deploy Rua, sign in, add the apex domain, then set `rua_self` from the domain page and apply again.

The wildcard `*._report._dmarc.reports.<domain>` record authorizes Rua to receive reports for any tenant's domain. Without it, receivers that implement RFC 7489 section 7.1 drop reports addressed to a different domain.
