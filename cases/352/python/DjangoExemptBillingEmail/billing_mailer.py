class BillingMailer:
    @staticmethod
    def queue_change(user_id, email):
        return {
            "event": "billing_email_change",
            "user_id": user_id,
            "email": email,
        }
