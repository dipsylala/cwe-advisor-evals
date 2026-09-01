from jinja2 import Environment


class TemplatePreviewRenderer:
    def __init__(self):
        self.env = Environment(autoescape=True)

    def render_preview(self, draft, context):
        # SAST FINDING: CWE-94 (Improper Control of Generation of Code) reported here. Sink is the next statement.
        template = self.env.from_string(draft.source)
        return template.render(context)
