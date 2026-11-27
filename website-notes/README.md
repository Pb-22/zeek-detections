# Website notes

[Detector families and packet tests](FAMILIES.md) describe file roles, links between helper callouts, source downloads and PCAP as the first consumer test. The notes remain separate from executable scripts and do not change the loader or package version.

These files supply the interactive explanations on [zeek.brimerica.com](https://zeek.brimerica.com). The website retrieves a script and its notes from the same repository commit.

## Keep notes beside the source

```text
scripts/modbus-write-illegal-function.zeek
website-notes/modbus-write-illegal-function.json
```

The notes tree mirrors the script tree. A nested script such as `scripts/example/check.zeek` uses `website-notes/example/check.json`. The `path` field names the exact script path.

Change a script and its corresponding explanations together in one commit. Notes describe the actual syntax, inputs, matching conditions, state and output. The website follows repository updates on its normal refresh schedule.

## Source placement

Section ranges use source snippets in `code`. The website finds those snippets in the current script and calculates the displayed line numbers. Empty lines and edge whitespace are ignored during placement, so adding lines above a section moves its callout automatically.

A repeated block can carry `before`, containing the immediately preceding source lines that distinguish its location. Existing files show this for repeated PKINIT record fields and cleanup statements.

Notice placeholders use a complete source line in `anchor` and the exact argument fragment in `text`. An optional `occurrence` selects a repeated fragment on that line. The website derives the current line number and highlights that argument when the placeholder is selected.

The source snippet and its surrounding context determine placement. Sections with a clear match remain interactive. A changed or ambiguous snippet stays available as ordinary readable code while the other mapped sections continue to work.

## Small example

This shows one section; the maintained files contain the complete explanations and notice templates.

```json
{
  "schema_version": 1,
  "path": "scripts/modbus-write-illegal-function.zeek",
  "topics": [
    {
      "id": "log-action",
      "title": "Select the standard log action",
      "description": "The action set sends this notice through the standard Notice logging path.",
      "ranges": [
        {"code": "$actions=set(Notice::ACTION_LOG),"}
      ],
      "links": []
    }
  ],
  "notice": {}
}
```

Each notice field is an ordered list of literal text and placeholder objects. For example, a function placeholder can use:

```json
{
  "token": "%02d",
  "label": "Register write function",
  "sources": [
    {
      "anchor": "headers$function_code - 0x80),",
      "text": "headers$function_code - 0x80"
    }
  ]
}
```

## Package separation

The package installs executable scripts from `scripts/`. Its publisher loader selects those scripts. This directory supplies inert website data and is separate from that runtime selection.

Notes edits need only the corresponding JSON update and Git push. They are outside the package checksum inventory and release numbering. The website computes placement from the fetched source; notes carry source text instead of author-maintained hashes, commit pins or line-number approvals.
