# Writing an Adapter

An adapter turns a tool output into structured Finding objects that every interface and report understands.

## The base class

whaxon.adapters.base.Adapter is an ABC with one required method:

    from whaxon.adapters.base import Adapter
    from whaxon.core.findings import Finding


    class MyAdapter(Adapter):
        tool_id = mytool   # must match an id in data/tools.json

        def parse(self, lines, ctx=None):
            return []

Finding accepts:

- kind (str): e.g. open_port, ntlm_hash, smb_share, impacket_loot
- severity (str): critical / high / medium / low / info
- source (str): usually the tool id
- raw_line (str): original line, truncated
- data (dict): structured payload
- cvss (float or None): CVSS score
- cwe (str): e.g. CWE-522
- impact (str): business impact
- remediation (str): remediation advice
- references (list[str]): URLs

## Registration

At module bottom:

    from whaxon.adapters import register
    register(MyAdapter())

Ensure the module is imported at startup - append to src/whaxon/adapters/__init__.py:

    from . import myadapter  # noqa: F401

The registry is a plain dict keyed by tool_id; the runner looks it up in _publish_findings.

## Consuming ctx

ctx carries information the runner knows but the raw output does not:

    def parse(self, lines, ctx=None):
        ctx = ctx or {}
        if isinstance(lines, list):
            text = chr(10).join(
                str(item[1]) if isinstance(item, tuple) else str(item)
                for item in lines
            )
        else:
            text = lines or ""

        extra = (ctx.get("extra_args") or "").strip()
        argv = ctx.get("argv") or []
        subtool = extra.split()[0] if extra else (argv[1] if len(argv) > 1 else "")

        if subtool == secretsdump:
            return self._parse_a(text)
        ...

See src/whaxon/adapters/impacket.py for the canonical pattern.

## Testing

Write parser tests against a stub of the tool output - no subprocess. Reference: tests/test_impacket_adapter.py.

    python -m pytest tests/test_myadapter.py -v

## Current adapters

- NmapAdapter (nmap): service table, 16 entries
- NiktoAdapter (nikto): issue patterns, 13 entries
- SqlmapAdapter (sqlmap): injection types + DBMS extraction
- BurpAdapter (burp): parses Burp XML (file import)
- HashcatAdapter (hashcat): cracked-hash lines
- ImpacketAdapter (impacket): secretsdump / smbclient / wmiexec
- MsfAdapter (msf): module runs, session creation

## Anti-patterns

- Do not spawn the tool from parse() - the runner already did.
- Do not mutate the lines list; read it.
- Do not swallow exceptions; a raised error is caught and logged with the tool id.
- Do not commit secrets in data payloads.