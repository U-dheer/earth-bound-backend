import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.MAIL_HOST,
      port: Number(process.env.MAIL_PORT),
      secure: false,
      auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS,
      },
    });
  }

  async sendPasswordResetEmail(to: string, OTP: string) {
    const templatePath = path.join(
      __dirname,
      '../templates/password-reset.html',
    );
    let htmlTemplate = fs.readFileSync(templatePath, 'utf-8');

    // Replace placeholders
    htmlTemplate = htmlTemplate
      .replace('{{OTP}}', OTP)
      .replace('{{YEAR}}', new Date().getFullYear().toString());

    const MailOptions = {
      from: 'EarthBound <no-reply@earth-bound.com>',
      to,
      subject: 'Password Reset Verification Code',
      html: htmlTemplate,
    };

    await this.transporter.sendMail(MailOptions);
  }
}
