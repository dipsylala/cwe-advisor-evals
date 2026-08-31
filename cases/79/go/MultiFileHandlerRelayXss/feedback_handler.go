package feedback

import "net/http"

// FeedbackRequest carries the raw form fields submitted by a visitor through
// the support widget's feedback form.
type FeedbackRequest struct {
	Author  string
	Message string
}

// SubmitFeedbackHandler receives visitor feedback posted from the support
// widget and hands it off to the feedback service for processing and
// rendering back into the page.
func SubmitFeedbackHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	req := FeedbackRequest{
		Author:  r.FormValue("author"),
		Message: r.FormValue("message"),
	}

	svc := NewFeedbackService()
	if err := svc.HandleSubmission(w, req); err != nil {
		http.Error(w, "unable to process feedback", http.StatusInternalServerError)
	}
}
