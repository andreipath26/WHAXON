# archive/

Dead code kept for historical context. **Not part of the build.**

## flask-legacy/

The predecessor project (Backforge), a Flask app that WHAXON replaced
in v0.1. Nothing in `src/whaxon/` imports from here. Nothing in the
test suite runs against it. If you are looking for how WHAXON works,
read `src/whaxon/` — not this directory.

If you are certain it will never be needed, delete this directory in
a single commit; no code depends on it.
