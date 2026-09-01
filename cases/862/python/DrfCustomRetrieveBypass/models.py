class Invoice:
    objects = None

    def __init__(self, invoice_id, owner_id, total_cents):
        self.id = invoice_id
        self.owner_id = owner_id
        self.total_cents = total_cents
