package com.burnbox.notification;

public interface EmailSenderClient {
    void send(String to, String subject, String body) throws Exception;
}
