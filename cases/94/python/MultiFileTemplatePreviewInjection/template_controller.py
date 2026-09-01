from .template_renderer import TemplatePreviewRenderer
from .template_store import TemplateDraftStore


class TemplatePreviewController:
    def __init__(self, store=None, renderer=None):
        self.store = store or TemplateDraftStore()
        self.renderer = renderer or TemplatePreviewRenderer()

    def preview(self, request):
        template_source = request.json.get("template")
        if not template_source:
            return {"error": "template is required"}, 400

        draft = self.store.save_draft(request.user.id, template_source)
        html = self.renderer.render_preview(draft, {
            "user": request.user,
            "campaign": request.json.get("campaign", {})
        })
        return {"preview": html}, 200
