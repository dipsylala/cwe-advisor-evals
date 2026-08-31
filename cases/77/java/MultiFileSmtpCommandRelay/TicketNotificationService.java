package com.example.support;

import java.util.logging.Logger;

/**
 * Turns an incoming ticket submission into an outbound acknowledgement
 * envelope and hands it to the relay client. The requester's own address
 * is threaded through as the reply-to so agents can respond directly.
 */
public class TicketNotificationService {

    private static final Logger LOG = Logger.getLogger(TicketNotificationService.class.getName());

    private final SmtpRelayClient relayClient;

    public TicketNotificationService(SmtpRelayClient relayClient) {
        this.relayClient = relayClient;
    }

    public void notifyAgent(TicketSubmission submission) {
        LOG.info("New ticket received, subject length=" + submission.getSubject().length());

        MailEnvelope envelope = new MailEnvelope(
                submission.getRequesterEmail(),
                "support-queue@example.com",
                "Ticket received: " + submission.getSubject());

        relayClient.sendAcknowledgement(envelope);
    }
}

class MailEnvelope {
    private final String replyTo;
    private final String recipient;
    private final String subjectLine;

    MailEnvelope(String replyTo, String recipient, String subjectLine) {
        this.replyTo = replyTo;
        this.recipient = recipient;
        this.subjectLine = subjectLine;
    }

    String getReplyTo() {
        return replyTo;
    }

    String getRecipient() {
        return recipient;
    }

    String getSubjectLine() {
        return subjectLine;
    }
}
