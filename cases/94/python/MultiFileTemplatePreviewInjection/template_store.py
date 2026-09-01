class TemplateDraft:
    def __init__(self, owner_id, source):
        self.owner_id = owner_id
        self.source = source


class TemplateDraftStore:
    def save_draft(self, owner_id, source):
        return TemplateDraft(owner_id, source)
