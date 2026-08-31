"""Controller for the product search endpoint."""

import time

from flask import Blueprint, request

from search_view import render_results

search_bp = Blueprint("search", __name__)


class SearchQuery:
    """Wraps a raw search term with the metadata the view layer needs."""

    def __init__(self, term, requested_at):
        self.term = term
        self.requested_at = requested_at


@search_bp.route("/search")
def search():
    raw_term = request.args.get("q", "")
    query = SearchQuery(term=raw_term, requested_at=time.time())
    return render_results(query)
