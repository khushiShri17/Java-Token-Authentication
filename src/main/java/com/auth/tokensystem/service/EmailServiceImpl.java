package com.auth.tokensystem.service;

import com.auth.tokensystem.config.AppProperties;
import com.auth.tokensystem.exception.EmailSendException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;
    private final AppProperties appProperties;

    @Override
    public void sendVerificationEmail(String email, String token) {
        String verificationUrl = appProperties.getUrls().getBase()
                + "/api/v1/users/verify/" + token;

        String html = """
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2>Email Verification</h2>
                    <p>Thank you for registering! Please verify your email address by clicking the button below:</p>
                    <a href="%s" style="display: inline-block; padding: 12px 24px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 4px;">
                        Verify Email
                    </a>
                    <p style="margin-top: 16px;">Or copy and paste this link in your browser:</p>
                    <p>%s</p>
                    <p><strong>This verification link will expire in 10 minutes.</strong></p>
                </div>
                """.formatted(verificationUrl, verificationUrl);

        sendEmail(email, "Verify Your Email Address", html);
    }

    @Override
    public void sendPasswordResetEmail(String email, String token) {
        String resetUrl = appProperties.getUrls().getBase()
                + "/api/v1/users/reset-password/" + token;

        String html = """
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2>Password Reset</h2>
                    <p>You requested a password reset. Click the button below to reset your password:</p>
                    <a href="%s" style="display: inline-block; padding: 12px 24px; background-color: #2196F3; color: white; text-decoration: none; border-radius: 4px;">
                        Reset Password
                    </a>
                    <p style="margin-top: 16px;">Or copy and paste this link in your browser:</p>
                    <p>%s</p>
                    <p><strong>This link will expire in 10 minutes.</strong></p>
                    <p>If you didn't request a password reset, please ignore this email.</p>
                </div>
                """.formatted(resetUrl, resetUrl);

        sendEmail(email, "Password Reset Request", html);
    }

    // Bug #8 fix: throws EmailSendException instead of silently swallowing errors
    private void sendEmail(String to, String subject, String htmlContent) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setFrom(appProperties.getMail().getSenderEmail());
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(htmlContent, true);
            mailSender.send(message);
        } catch (Exception e) {
            log.error("Failed to send email to {}: {}", to, e.getMessage());
            throw new EmailSendException("Failed to send email. Please try again later.", e);
        }
    }
}
