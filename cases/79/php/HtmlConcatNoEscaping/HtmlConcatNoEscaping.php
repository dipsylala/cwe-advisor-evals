<?php
// Product review card renderer for a storefront product page.

function fetchSubmittedReview() {
    // Reviewer name and review text as submitted via the review form.
    return [
        'author' => $_POST['author'] ?? '',
        'body' => $_POST['body'] ?? ''
    ];
}

function renderReviewCard() {
    $review = fetchSubmittedReview();

    $html = '<div class="review-card">';
    $html .= '<h3 class="review-author">' . $review['author'] . '</h3>';
    $html .= '<p class="review-body">' . $review['body'] . '</p>';
    $html .= '</div>';

    return $html;
}

$card = renderReviewCard();

// SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
echo $card;
