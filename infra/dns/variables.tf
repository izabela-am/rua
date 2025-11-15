variable "zone_id" {
  description = "Cloudflare zone ID for var.domain."
  type        = string
}

variable "domain" {
  description = "Apex domain Rua runs on, such as example.net."
  type        = string
}

variable "app_host" {
  description = "Hostname of the Render service, such as rua-api.onrender.com. The dashboard is served at rua.<domain>."
  type        = string
}

variable "resend_sending" {
  description = "Resend sending records for var.domain, copied from the Resend dashboard (Domains > DNS records)."
  type = object({
    dkim_name     = string # resend._domainkey
    dkim_value    = string # p=MIGfMA0...
    send_mx_name  = string # send
    send_mx_value = string # feedback-smtp.us-east-1.amazonses.com
    send_spf      = string # v=spf1 include:amazonses.com ~all
  })
}

variable "resend_inbound_mx" {
  description = "Resend inbound MX host for reports.<domain>, from the Resend dashboard (Receiving)."
  type        = string
}

variable "rua_self" {
  description = "Rua's own first domain: the report local part and verify token issued for var.domain by Rua itself."
  type = object({
    local_part   = string # d-7f3k9a2mq4xz
    verify_token = string
  })
  default = null
}

variable "dmarc_policy" {
  description = "DMARC policy for var.domain. Start at none; Rua's readiness check says when to raise it."
  type        = string
  default     = "none"
  validation {
    condition     = contains(["none", "quarantine", "reject"], var.dmarc_policy)
    error_message = "dmarc_policy must be none, quarantine or reject."
  }
}
