import type { Resend } from "resend";
import { log } from "../log.js";

export type Mail = { to: string; subject: string; text: string };
export type Mailer = { send(mail: Mail): Promise<void> };

export function resendMailer(resend: Resend, from: string): Mailer {
  return {
    async send(mail) {
      const { error } = await resend.emails.send({ from, to: mail.to, subject: mail.subject, text: mail.text });
      if (error) throw new Error(`resend send: ${error.message}`);
    },
  };
}

/** Development: alerts go to the log. */
export const logMailer: Mailer = {
  async send(mail) {
    log.info("mail (not sent)", mail);
  },
};
