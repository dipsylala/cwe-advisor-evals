package com.example.feedback;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;

public class FeedbackController {

    private final FeedbackRenderer renderer = new FeedbackRenderer();

    public void handleSubmit(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String rawComment = request.getParameter("comment");
        if (rawComment == null) {
            rawComment = "";
        }
        String authorName = request.getParameter("author");
        if (authorName == null) {
            authorName = "Anonymous";
        }

        FeedbackRenderer.FeedbackSubmission submission =
                new FeedbackRenderer.FeedbackSubmission(authorName, rawComment, Instant.now());
        renderer.renderConfirmation(submission, response);
    }
}
