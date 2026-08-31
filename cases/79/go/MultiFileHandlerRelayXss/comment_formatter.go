package feedback

import "strings"

// CommentFormatter prepares a raw Comment for display: trimming whitespace,
// capping the display-name length, and building a short preview excerpt of
// the message body.
type CommentFormatter struct{}

func NewCommentFormatter() *CommentFormatter {
	return &CommentFormatter{}
}

// PrepareForDisplay normalizes the author name and derives a bounded excerpt
// from the message. Neither step encodes the text for HTML output - that is
// left to whatever renders the comment.
func (f *CommentFormatter) PrepareForDisplay(c Comment) Comment {
	name := strings.TrimSpace(c.Author)
	if len(name) > 40 {
		name = name[:40] + "..."
	}
	c.Author = name
	c.Excerpt = summarize(c.Message)
	return c
}

func summarize(message string) string {
	message = strings.TrimSpace(message)
	if len(message) > 160 {
		return message[:160] + "..."
	}
	return message
}
