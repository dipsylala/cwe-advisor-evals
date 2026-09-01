package gorminvoice

import (
	"context"

	"gorm.io/gorm"
)

type Invoice struct {
	ID         string
	AccountID  string
	Status     string
	TotalCents int64
}

type InvoiceRepository struct {
	DB *gorm.DB
}

func (r *InvoiceRepository) Export(ctx context.Context, accountID string, status string, sort string) error {
	var invoices []Invoice
	return r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status).
		Order(sort).
		Find(&invoices).Error
}
