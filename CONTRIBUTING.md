## License Agreement

By submitting a Pull Request to WHAXON, you agree to the terms of our Contributor License Agreement (CLA), available at ./CLA.md.

You will be prompted by our CLA bot to sign before your contribution can be reviewed. The bot will comment on your PR with instructions.

Why this matters: WHAXON is dual-licensed under AGPL-3.0 and a commercial license. The CLA ensures we have the legal right to distribute your contribution under both licenses. Without signing, we cannot merge your code.

---

# Contributing to WHAXON

Thanks for your interest. Short version: open an issue first, keep PRs focused, run the tests.

## Setup

    git clone https://github.com/andreipath26/WHAXON.git
    cd WHAXON
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e ".[tui,gui,web,dev]"

## Before you open a PR

1. python -m pytest tests/ -q  (all green)
2. ruff check src tests  (no new warnings)
3. New code has tests. New adapters have a tests/test_<tool>_adapter.py.

## The boundary rule

whaxon.core and whaxon.adapters MUST NOT import whaxon.ai. core/ai_bridge.py is the only exception, and CI enforces this. See docs/architecture.md.

## Adding a new tool

1. Append an entry to data/tools.json (id, binary, args template)
2. Subclass whaxon.adapters.base.Adapter, implement parse()
3. register(MyAdapter()) at module level, import from adapters/__init__.py
4. Add tests/test_myadapter.py with a stub of the tool output

Full guide: docs/adapters.md.

## Adding an AI provider

Subclass whaxon.ai.providers.backends.base.LLMBackend. Implement chat(messages, timeout) -> str and available() -> (bool, str). Register in BACKENDS. Do not add SDK dependencies - use stdlib HTTP.

## Commit messages

Follow the existing style: feat(scope): ..., fix(correlator): ..., docs(ai): .... One feature per commit where practical.

## License

By contributing, you agree your contributions are licensed under AGPL-3.0-or-later.
