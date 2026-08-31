package com.example.support;

import javax.servlet.http.HttpServletRequest;

/**
 * Entry point for the public "contact support" web form. Reads the
 * submitted fields and hands them off to the notification layer so an
 * acknowledgement can be relayed back to the requester.
 */
public class TicketController {

    private final TicketNotificationService notificationService;

    public TicketController(TicketNotificationService notificationService) {
        this.notificationService = notificationService;
    }

    public void handleSubmit(HttpServletRequest request) {
        String subject = request.getParameter("subject");
        String requesterEmail = request.getParameter("requesterEmail");
        String body = request.getParameter("body");

        TicketSubmission submission = new TicketSubmission(subject, requesterEmail, body);
        notificationService.notifyAgent(submission);
    }
}

class TicketSubmission {
    private final String subject;
    private final String requesterEmail;
    private final String body;

    TicketSubmission(String subject, String requesterEmail, String body) {
        this.subject = subject;
        this.requesterEmail = requesterEmail;
        this.body = body;
    }

    String getSubject() {
        return subject;
    }

    String getRequesterEmail() {
        return requesterEmail;
    }

    String getBody() {
        return body;
    }
}
