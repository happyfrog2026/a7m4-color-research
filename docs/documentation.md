# Maintaining bilingual documentation

English | [简体中文](documentation_zh.md)

## File organization

- Keep `README.md` in English and `README_zh.md` in Simplified Chinese at the repository root.
- Put project-owned guides in `docs/`. Use lowercase topic names: `helper-guide.md` and `helper-guide_zh.md`.
- Every page links to its counterpart immediately below its title. Within each language, links to paired guides stay in that language.
- [documents.json](documents.json) is the single registry of page pairs and diagram exports. Add new pages there.
- Keep `LICENSE` and upstream licenses and notices in their original locations and languages. Frozen source excerpts are not translated.

## Updating a topic

1. Update the affected topic in both languages in the same change. Chinese may be used as the initial draft, but neither version is published as a completed translation until both are reviewed.
2. Preserve equivalent instructions, supported scope, warnings and results. Identifiers, command examples, schema names and filenames stay unchanged between languages.
3. Update shared facts from the code or confirmed records. Do not maintain a separate copy of a procedure in each README; link to its guide.
4. Edit diagrams in the Markdown pages. Export files and the package manifest are generated; do not edit them manually.
5. Run the two commands below and review the bilingual diff before committing.

```sh
python3 tools/docs.py sync
python3 tools/docs.py check
```

These commands operate only on repository documentation, diagrams and file manifests. They do not connect to a camera or export user logs.

## Automated checks

The checker verifies registered pairs, filename conventions, reciprocal language links, local link targets and anchors, same-language guide links, heading structure and identical shell/JSON examples. It also checks generated diagrams, the unchanged source-excerpt index and package file hashes. A GitHub workflow runs the same check on pushes and pull requests.

Automation catches structural drift; it cannot establish translation accuracy or actual device behavior. A reviewer must still compare meaning and verify claims against their source.

## Source comments and exceptions

Keep new code comments and docstrings in English. UI text, errors and CLI help strings are separate user-facing content and may remain Chinese where appropriate. Preserve upstream comments, copyright and license text.

Source excerpts have their own version and provenance. Documentation maintenance does not authorize editing that snapshot or changing its hash index to hide a source change.
