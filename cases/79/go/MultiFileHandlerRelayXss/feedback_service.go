package feedback

import (
	"log"
	"net/http"
	"time"
)

// Comment is the persisted/display representation of a feedback submission
// once the service layer has taken ownership of it.
type Comment struct {
	Author   string
	Message  string
	Excerpt  string
	PostedAt time.Time
}

// FeedbackService coordinates bookkeeping and rendering of a single feedback
// submission on its way from the HTTP layer to the page.
type FeedbackService struct{}

func NewFeedbackService() *FeedbackService {
	return &FeedbackService{}
}

// HandleSubmission wraps the incoming request in a Comment, records an audit
// log entry, and delegates formatting and rendering to the downstream
// collaborators.
func (s *FeedbackService) HandleSubmission(w http.ResponseWriter, req FeedbackRequest) error {
	comment := Comment{
		Author:   req.Author,
		Message:  req.Message,
		PostedAt: time.Now(),
	}

	log.Printf("feedback received: author=%q postedAt=%s", comment.Author, comment.PostedAt.Format(time.RFC3339))

	formatter := NewCommentFormatter()
	prepared := formatter.PrepareForDisplay(comment)

	view := NewCommentView(w)
	return view.Render(prepared)
}
