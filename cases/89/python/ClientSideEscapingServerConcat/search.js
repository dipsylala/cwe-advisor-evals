function submitSearch(term) {
  const escaped = term.replace(/'/g, "\\'");
  return fetch('/api/search?term=' + encodeURIComponent(escaped));
}
