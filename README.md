# agrep

Universal, agent-first search across code, legal docs, product docs, and logs.

**GitHub description** (for repo About):  
`Agent-first search: natural-language queries, domain-aware ranking, and JSONL output for code, legal, docs, and logs.`

**License:** [MIT](LICENSE)

`agrep` is a deterministic retrieval engine built for AI coding agents and human power users. It combines text search, domain-aware ranking, NL query translation, and machine-readable output in one interface.

## v1 Scope

`v1.0.0` includes:

- `query` command with deterministic scoring and ordering
- Natural-language to query-plan translation (`--show-plan`)
- Domain routing (`auto`, `code`, `legal`, `docs`, `logs`)
- JSONL and table outputs
- Recursive file scanning with include/exclude filters

## Why `agrep`

Classic grep is great for text speed. Agents need more:

- Stable, machine-readable results with deterministic IDs
- Natural-language query support that compiles to transparent query plans
- Domain-aware retrieval (code, legal, docs, logs)
- Token-budget-aware snippets for LLM workflows
- Trust signals (confidence, parser/OCR errors, freshness)

## How It Differs From Traditional Grep

`grep` and `ripgrep` are excellent text match engines. `agrep` is a retrieval workflow engine for agents and cross-domain search.

| Capability | `grep` / `ripgrep` | `agrep` |
|---|---|---|
| Primary model | Text/regex matching | Intent-driven retrieval + ranking |
| Input style | Explicit pattern only | Explicit pattern or natural language |
| Output focus | Human terminal output | Human + machine (`table` + `jsonl`) |
| Result ordering | Match order | Deterministic relevance scoring |
| Explainability | Limited | `--show-plan` + score breakdown |
| Domain awareness | Mostly file/path based | Native domain routing (`code`, `legal`, `docs`, `logs`, `auto`) |
| Agent integration | Parse CLI text manually | Structured records with stable IDs |
| Triage workflow | Manual | Built for query -> rank -> decision flow |

When to use what:

- Use `grep`/`ripgrep` for fast raw text lookup and regex-heavy one-off searches.
- Use `agrep` when you need explainable ranking, NL queries, domain routing, and automation-friendly output.

## Core Capabilities

- `--format=jsonl` streaming output for tools and agents
- Hybrid retrieval: text prefilter + structure-aware refinement + reranking
- Universal schema across domains
- Incremental indexing with stale/fallback metadata
- Deterministic ordering for reproducible automation

## Domains

`agrep` uses a universal core with pluggable domain packs:

- `code`: symbols, definitions/references, AST patterns
- `legal`: clauses, defined terms, citation-aware anchors
- `docs`: sections, headings, tables, footnotes
- `logs`: timestamps, session correlation, error clusters

## Quickstart

```bash
# Build
cargo build --release

# Run
./target/release/agrep query "where is auth enforced?" --domain=code --mode=hybrid --format=jsonl --show-plan
```

## Search scope

agrep searches **across all files and folders** under the path you give:

- **`--path <dir>`** — Recursively scans the directory and all subdirectories. One run searches every matching file in the tree.
- **`--include <pattern>`** — Only files whose path contains the pattern (e.g. `--include code`).
- **`--exclude <pattern>`** — Skip paths containing the pattern (e.g. `--exclude node_modules`). Default excludes include `.git` and `target`.

Results are **line-level** (one snippet per hit). Use **`--context-lines <n>`** to include `n` lines above and below each match. To get the full method, use the `path` and `anchor` (line number) from the result and open the file in your editor (e.g. “Expand selection to function”).

## Quick Examples

```bash
# Code: locate auth enforcement points (searches all files under path)
agrep query "where is auth enforced?" --path . --domain=code --format=jsonl

# Legal: find termination-for-convenience clauses
agrep query "termination for convenience" --domain=legal --format=jsonl

# With context lines and query plan
agrep query "login or session creation" --path testdata --domain=code --format=table --max-results 10 --context-lines 3 --show-plan

# Auto-detect mixed repositories
agrep query "data retention policy exceptions" --domain=auto --format=jsonl
```

## Documentation & reports

- **Interactive guide** (grep origin, NL translation, use cases, examples, how to parse): [`agrep-interactive-guide.html`](agrep-interactive-guide.html) — open in a browser.
- **Test report**: [`reports/agrep-v1-test-report.html`](reports/agrep-v1-test-report.html) — end-to-end flow, usage, triage, outputs.

## Output Contract (JSONL)

Each result is a deterministic `MatchRecord`:

```json
{
  "id": "sha1(source:path:anchor:span:query)",
  "source_type": "code|legal|docs|logs",
  "path": "contracts/master-services-agreement.pdf",
  "anchor": "section-12.2",
  "span": { "start": 430, "end": 476 },
  "snippet": "...either party may terminate for convenience...",
  "score": 0.92,
  "score_breakdown": {
    "domain": 0.40,
    "structure": 0.22,
    "path": 0.15,
    "proximity": 0.15
  },
  "signals": {
    "confidence": 0.87,
    "parse_error": false,
    "ocr_error": false,
    "generated": false
  },
  "freshness": {
    "indexed_at": "2026-02-20T12:00:00Z",
    "stale": false
  }
}
```

## Architecture

- `agrep-core`: query IR, planner, executor, ranking orchestration
- `agrep-ingest`: parsers/chunkers for code, PDF, DOCX, HTML, logs
- `agrep-index`: incremental index + metadata store (post-v1)
- `agrep-domains-*`: domain plugins (code/legal/docs/logs)
- `agrep-nl`: deterministic NL-to-plan compiler
- `agrep-cli`: CLI interface

## Design Principles

- Deterministic by default
- Transparent NL translation (show compiled plan)
- Fast first result, not just fast total scan
- Domain-aware ranking without breaking schema consistency
- Auditability for high-trust environments

## Roadmap

- [ ] v1.1: Expanded legal/domain heuristics and stronger mixed-domain routing
- [ ] v1.2: Advanced policy profiles and improved trust-signal calibration
- [ ] v1.3: Larger-scale indexing optimizations and lower-latency streaming
- [ ] v1.4: Deeper MCP integrations and enterprise deployment tooling
- [ ] v1.5: Cross-repo retrieval and federated search controls

## Status

`agrep` is production-ready at `v1`.

## Contributing

Issues and design feedback are welcome. If you open an issue, include:

- Domain (`code`, `legal`, `docs`, `logs`, or `mixed`)
- Query example
- Expected vs actual results
- Repo/document scale and performance constraints

## Vision

One search engine for agents and humans across all engineering knowledge surfaces.
