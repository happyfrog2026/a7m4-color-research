#!/usr/bin/env python3
"""Synchronize and validate bilingual project documentation without device I/O."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / 'docs/documents.json'
MANIFEST = ROOT / 'docs/package-manifest.json'
SOURCE_INDEX = ROOT / 'docs/source-index.json'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def registry():
    value = json.loads(REGISTRY.read_text(encoding='utf-8'))
    require(value.get('schema') == 'a7m4-bilingual-documents/1', 'Unknown document registry')
    seen = set()
    for pair in value['pairs']:
        for language in ('en', 'zh'):
            path = pair[language]
            relative = PurePosixPath(path)
            require(not relative.is_absolute() and '..' not in relative.parts
                    and str(relative) == path and path not in seen,
                    'Invalid or duplicate registered document: ' + path)
            seen.add(path)
        en, zh = PurePosixPath(pair['en']), PurePosixPath(pair['zh'])
        require(zh == en.with_name(en.stem + '_zh' + en.suffix),
                'Chinese filename must use the lowercase _zh suffix: ' + pair['id'])
        require(en.suffix == '.md' and (str(en) == 'README.md'
                or en.parts[0] == 'docs' and en.stem == en.stem.lower()),
                'Use root README or lowercase topics under docs/: ' + str(en))
    return value


def public_files():
    paths = {ROOT / name for name in ('README.md', 'README_zh.md', 'LICENSE', '.gitignore')}
    for directory in ('docs', 'cli', 'examples', 'source', 'tools', '.github'):
        for path in (ROOT / directory).rglob('*'):
            if not path.is_file() or '__pycache__' in path.parts:
                continue
            if path.name == '.DS_Store' or path.name.startswith('._') or path.suffix == '.pyc':
                continue
            paths.add(path)
    paths.discard(MANIFEST)
    require(all(not p.is_symlink() for p in paths), 'Symlinks are not documentation package inputs')
    return sorted(paths)


def expected_manifest():
    return {
        'schema': 'a7m4-public-research-package/1',
        'source_version': '0.5.1-alpha.62',
        'project_license': 'PolyForm-Noncommercial-1.0.0',
        'existing_source_licenses_preserved': True,
        'camera_io_performed_for_publication': False,
        'documentation_languages': ['en', 'zh'],
        'files': [dict(path=p.relative_to(ROOT).as_posix(), bytes=p.stat().st_size,
                       sha256=digest(p.read_bytes())) for p in public_files()],
    }


def check_source_index():
    index = json.loads(SOURCE_INDEX.read_text(encoding='utf-8'))
    for row in index['files']:
        relative = PurePosixPath(row['path'])
        require(relative.parts[0] == 'source' and '..' not in relative.parts,
                'Invalid source-index path')
        raw = (ROOT / row['path']).read_bytes()
        require(len(raw) == row['bytes'] and digest(raw) == row['sha256'],
                'Frozen source excerpt changed: ' + row['path'])


def diagram_export(export):
    text = (ROOT / export['document']).read_text(encoding='utf-8')
    blocks = re.findall(r'^```mermaid\s*\n(.*?)^```\s*$', text, flags=re.M | re.S)
    require(len(blocks) == 1, 'Expected one Mermaid diagram: ' + export['document'])
    diagram = blocks[0].strip() + '\n'
    require(not re.search(r'0x[0-9a-fA-F]+|(?:\d{1,3}\.){3}\d{1,3}|https?://|/(?:Users|Volumes|tmp|usr|cp)/', diagram),
            'High-level diagrams must not contain concrete addresses: ' + export['document'])
    return diagram


def write_if_changed(path, text):
    if not path.is_file() or path.read_text(encoding='utf-8') != text:
        path.write_text(text, encoding='utf-8')


def synchronize(value):
    check_source_index()
    for export in value['exports']:
        write_if_changed(ROOT / export['output'], diagram_export(export))
    write_if_changed(MANIFEST, json.dumps(expected_manifest(), ensure_ascii=False, indent=2) + '\n')


def without_fences(text):
    return re.sub(r'^```[^\n]*\n.*?^```\s*$', '', text, flags=re.M | re.S)


def anchors(text):
    counts = {}
    found = set()
    for heading in re.findall(r'^#{1,6}\s+(.+)$', without_fences(text), flags=re.M):
        heading = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', heading)
        slug = re.sub(r'[^\w\s-]', '', heading.lower()).strip().replace(' ', '-')
        occurrence = counts.get(slug, 0)
        counts[slug] = occurrence + 1
        found.add(slug if not occurrence else slug + '-' + str(occurrence))
    return found


def check_links(path, text, language, counterpart, languages, inventory):
    relative_page = path.relative_to(ROOT)
    for target in re.findall(r'!?\[[^\]]*\]\(([^)]+)\)', without_fences(text)):
        target = target.strip('<>')
        parts = urlsplit(target)
        if parts.scheme or parts.netloc:
            continue
        destination = unquote(parts.path)
        relative = (relative_page.as_posix() if not destination else
                    posixpath.normpath((relative_page.parent / destination).as_posix()))
        require(not relative.startswith('../') and relative in inventory,
                f'{relative_page}: missing or case-mismatched local target {target}')
        if relative in languages and relative != counterpart:
            require(languages[relative] == language,
                    f'{relative_page}: use the same-language guide for {target}')
        if parts.fragment:
            fragment = unquote(parts.fragment)
            code_line = re.fullmatch(r'L\d+(?:-L\d+)?', fragment)
            require(code_line or fragment in anchors((ROOT / relative).read_text(encoding='utf-8')),
                    f'{relative_page}: missing anchor {target}')


def validate(value):
    languages = {pair[language]: language for pair in value['pairs'] for language in ('en', 'zh')}
    actual = {p.relative_to(ROOT).as_posix() for p in ROOT.glob('*.md') if p.name != 'AGENTS.md'}
    actual.update(p.relative_to(ROOT).as_posix() for p in (ROOT / 'docs').rglob('*.md'))
    require(actual == set(languages), 'Register every project-owned page; remove stale root guides: '
            + str(sorted(actual.symmetric_difference(languages))))
    inventory = {p.relative_to(ROOT).as_posix() for p in public_files()}
    inventory.add(MANIFEST.relative_to(ROOT).as_posix())
    inventory.update(p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*')
                     if p.is_dir() and '.git' not in p.parts and '.local-release' not in p.parts)
    require(not any(p.name.startswith('README') and p.suffix == '.md'
                    and p.relative_to(ROOT).as_posix() not in languages
                    for p in ROOT.rglob('*.md') if 'source' not in p.parts
                    and '.git' not in p.parts and '.local-release' not in p.parts),
            'A project README is missing from the language registry')
    for pair in value['pairs']:
        texts = {}
        for language in ('en', 'zh'):
            relative = pair[language]
            other = pair['zh' if language == 'en' else 'en']
            text = (ROOT / relative).read_text(encoding='utf-8')
            texts[language] = text
            require(text.startswith('# ') and f']({PurePosixPath(other).name})' in '\n'.join(text.splitlines()[1:6]),
                    'Missing language switch beneath title: ' + relative)
            check_links(ROOT / relative, text, language, other, languages, inventory)
        headings = lambda s: re.findall(r'^(#{1,6})\s+', without_fences(s), flags=re.M)
        require(headings(texts['en']) == headings(texts['zh']), 'Heading structure differs: ' + pair['id'])
        examples = lambda s: re.findall(r'^```(sh|bash|shell|json)\s*\n(.*?)^```\s*$', s, flags=re.M | re.S)
        require(examples(texts['en']) == examples(texts['zh']), 'Shell/JSON examples differ: ' + pair['id'])
    for export in value['exports']:
        require((ROOT / export['output']).read_text(encoding='utf-8') == diagram_export(export),
                'Diagram export is stale; run sync: ' + export['output'])
    check_source_index()
    require(json.loads(MANIFEST.read_text(encoding='utf-8')) == expected_manifest(),
            'Package manifest is stale; run sync')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('sync', 'check'))
    args = parser.parse_args()
    try:
        value = registry()
        if args.command == 'sync':
            synchronize(value)
        validate(value)
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, f'Documentation check failed: {error}\n')
    print(f'Documentation {args.command}: PASS ({len(value["pairs"])} bilingual pairs; no device I/O).')


if __name__ == '__main__':
    main()
