package com.burnbox.notification;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

@Component
public class DefaultEmailSenderClient implements EmailSenderClient {

    private final ObjectProvider<JavaMailSender> mailSenderProvider;

    public DefaultEmailSenderClient(ObjectProvider<JavaMailSender> mailSenderProvider) {
        this.mailSenderProvider = mailSenderProvider;
    }

    @Override
    public void send(String to, String subject, String body) throws Exception {
        JavaMailSender mailSender = mailSenderProvider.getIfAvailable();
        if (mailSender == null) {
            return;
        }

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setFrom("no-reply@burnbox.io");
        message.setSubject(subject);
        message.setText(body);
        mailSender.send(message);
    }
}
