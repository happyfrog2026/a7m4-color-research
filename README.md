# A7M4 Color Research

English | [简体中文](README_zh.md)

[Telegram (recommended)](https://t.me/+gmbCDvVseX41Nzcx)
Please check the group announcements before downloading and using the tool.
Allow at least 20 minutes to apply changes and at least 35 minutes to restore a backup.
The current version supports FL2/FL3/M9 filter import over USB-C and custom electronic shutter sounds.
This project is for personal study only. Commercial use is prohibited.
Use is at your own risk; users are responsible for their actions.

Color pipeline and creative looks research for the A7M4.

This repository is the release home for project documentation and selected release artifacts.

## Research materials

These materials provide alpha.62 research notes, shared CLI entry points and source excerpts for review and further study.

| Entry | Contents |
| --- | --- |
| [High-level workflow](docs/architecture.md) | Installation, restoration from a backup, user cold starts and functional checks |
| [Helper guide](docs/helper-guide.md) | Module map, local checks, backup validation and shared CLI usage |
| [Upstream research](docs/upstream-attribution.md) | Research sources listed in the App's References and About page |
| [Source excerpts](source/) | Shared helpers and GUI callers from the corresponding version |
| [Bilingual documentation](docs/documentation.md) | Naming, language links and synchronized updates |

### Supported scope

- A7M4 with a supported 6.02 build; actual jobs check the body and version.
- FL2/FL3, the fixed M9 recipe, Custom1 display names and icons, and electronic shutter sounds.
- Restoration of supported feature areas from a pre-modification original backup; an intermediate checkpoint is not completion.
- Restore from the original backup as instructed before applying a new configuration.

The source excerpts are for reading and further development. Runtime entry points reuse the complete environment of a matching App; the excerpts are not a standalone installation directory. See the [helper guide](docs/helper-guide.md) for the driver version and runtime requirements.

### Local CLI checks

```sh
./cli/a7m4-toolbox --help
./cli/a7m4-toolbox driver status
./cli/check-local ./new-local-check
./cli/check-backup /absolute/path/original.a7capture
./cli/export-logs /absolute/path/new-history.zip
```

These examples check only the local environment, existing backups and local logs. They do not open a camera service. Use a new directory or filename for output. Follow the matching App's prompts for actual camera operations and keep the camera connected; disconnect only when explicitly instructed to perform a cold start.

## License

New documentation and convenience entry points in this repository follow the [PolyForm Noncommercial License 1.0.0](LICENSE). Existing source excerpts and third-party components retain their original licenses, copyrights and required notices; see [Third-party notices](docs/third-party-notices.md).
