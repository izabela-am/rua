output "dmarc_record" {
  value = cloudflare_dns_record.dmarc.content
}

output "reports_domain" {
  value = local.reports
}
