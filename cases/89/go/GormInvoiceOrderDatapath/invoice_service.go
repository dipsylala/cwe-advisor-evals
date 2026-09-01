package gorminvoice

import "context"

type InvoiceService struct {
	Repository *InvoiceRepository
}

func (s *InvoiceService) ExportInvoices(ctx context.Context, accountID string, status string, sort string) error {
	return s.Repository.Export(ctx, accountID, status, sort)
}
