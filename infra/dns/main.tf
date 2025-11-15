locals {
  reports = "reports.${var.domain}"
  rua     = var.rua_self == null ? "" : "; rua=mailto:${var.rua_self.local_part}@${local.reports}"
}

# Dashboard and API.
resource "cloudflare_dns_record" "app" {
  zone_id = var.zone_id
  name    = "rua.${var.domain}"
  type    = "CNAME"
  content = var.app_host
  proxied = false
  ttl     = 300
}

# Outbound mail through Resend: magic links and alerts.
resource "cloudflare_dns_record" "resend_dkim" {
  zone_id = var.zone_id
  name    = "${var.resend_sending.dkim_name}.${var.domain}"
  type    = "TXT"
  content = var.resend_sending.dkim_value
  ttl     = 3600
}

resource "cloudflare_dns_record" "resend_send_mx" {
  zone_id  = var.zone_id
  name     = "${var.resend_sending.send_mx_name}.${var.domain}"
  type     = "MX"
  content  = var.resend_sending.send_mx_value
  priority = 10
  ttl      = 3600
}

resource "cloudflare_dns_record" "resend_send_spf" {
  zone_id = var.zone_id
  name    = "${var.resend_sending.send_mx_name}.${var.domain}"
  type    = "TXT"
  content = var.resend_sending.send_spf
  ttl     = 3600
}

# Inbound report mail. Every d-<random>@reports.<domain> lands in Resend.
resource "cloudflare_dns_record" "reports_mx" {
  zone_id  = var.zone_id
  name     = local.reports
  type     = "MX"
  content  = var.resend_inbound_mx
  priority = 10
  ttl      = 3600
}

# The apex sends no mail of its own.
resource "cloudflare_dns_record" "apex_spf" {
  zone_id = var.zone_id
  name    = var.domain
  type    = "TXT"
  content = "v=spf1 -all"
  ttl     = 3600
}

# Rua reports on its own domain.
resource "cloudflare_dns_record" "dmarc" {
  zone_id = var.zone_id
  name    = "_dmarc.${var.domain}"
  type    = "TXT"
  content = "v=DMARC1; p=${var.dmarc_policy}; adkim=r; aspf=r${local.rua}"
  ttl     = 3600
}

resource "cloudflare_dns_record" "rua_verify" {
  count   = var.rua_self == null ? 0 : 1
  zone_id = var.zone_id
  name    = "_rua.${var.domain}"
  type    = "TXT"
  content = "rua-verify=${var.rua_self.verify_token}"
  ttl     = 300
}

# Receivers that send reports for one domain to an address at another domain
# check that the receiving domain agrees (RFC 7489 section 7.1). The wildcard
# under _report._dmarc accepts reports for any tenant domain.
resource "cloudflare_dns_record" "external_report_auth" {
  zone_id = var.zone_id
  name    = "*._report._dmarc.${local.reports}"
  type    = "TXT"
  content = "v=DMARC1"
  ttl     = 3600
}
