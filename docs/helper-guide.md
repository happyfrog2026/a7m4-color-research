# Helper guide and CLI usage

English | [简体中文](helper-guide_zh.md)

These materials correspond to the alpha.62 shared driver snapshot: **0.5.1-alpha.62**. The launcher accepts only an installed App with that matching driver version. A release-page tag does not replace the runtime version check.

The GUI and CLI share planning, scope checks, job coordination, result verification and exit handling. `source/` preserves the reading structure; execution requires the complete resources, manifests and environment in the matching App.

## Where to start

| Goal | Entry point | Scope |
| --- | --- | --- |
| Inspect version and capabilities | `./cli/a7m4-toolbox driver status` | Local historical metadata, not the camera's current state |
| Check dependencies and the helper inventory | `./cli/check-local NEW_DIRECTORY` | Local; does not create a USB backend |
| Validate a portable backup | `./cli/check-backup ORIGINAL.a7capture` | Local archive |
| Export retained diagnostic history | `./cli/export-logs NEW_HISTORY.zip` | Current user's local records |
| Check the connection | `driver connection-check` | Reads host USB information; does not open a camera service |
| Read the current state | `driver backup` | Explicit camera session |
| Freeze or plan the final selection | `driver selected-freeze`, `selected-plan` | Local |
| Apply the final selection | `driver selected-install` | Explicit camera operation |
| Plan restoration from an original backup | `driver backup-target-plan` | Local |
| Restore, resume or verify after startup | `driver backup-target-restore`, `backup-target-verify` | Explicit camera operation |
| Record final user observations | `driver backup-target-acceptance` | Checks retained local evidence |

Append each `driver …` entry to `./cli/a7m4-toolbox`. Consult that command's `--help` for its complete arguments. Run the examples from the repository root.

The convenience scripts do not elevate privileges, supply user acknowledgements, retry or advance checkpoints automatically. Set `A7M4_APP` to the matching `.app` if it is not in the default location. The App manages the GUI's administrator session; these scripts do not create or take over that session.

## Source reading map

| Topic | Source entry points |
| --- | --- |
| Shared CLI, arguments and results | [cli.py](../source/a7m4/toolbox/cli.py), [run_toolbox.py](../source/run_toolbox.py), [run_research.py](../source/run_research.py) |
| Current backup scope and input validation | [resource_profile.py](../source/a7m4/resource_profile.py), [capture_inputs.py](../source/a7m4/toolbox/capture_inputs.py) |
| Backup reads and adoption of existing data | [usb_read.py](../source/a7m4/toolbox/usb_read.py), [capture_recovery.py](../source/a7m4/toolbox/capture_recovery.py) |
| Final selection and asset bindings | [selected_config.py](../source/a7m4/toolbox/selected_config.py), [selected_plan.py](../source/a7m4/toolbox/selected_plan.py) |
| Current installation flow | [selected_job.py](../source/a7m4/toolbox/selected_job.py), [selected_stages.py](../source/a7m4/toolbox/selected_stages.py) |
| Restoration plan from original and current state | [backup_target_scope.py](../source/a7m4/toolbox/backup_target_scope.py), [backup_target_execution.py](../source/a7m4/toolbox/backup_target_execution.py) |
| Restoration stages, checkpoints and final acceptance | [backup_target_flow.py](../source/a7m4/toolbox/backup_target_flow.py), [backup_target_job.py](../source/a7m4/toolbox/backup_target_job.py), [backup_target_resume.py](../source/a7m4/toolbox/backup_target_resume.py) |
| ST protection and post-startup state checks | [restore_st_settings.py](../source/a7m4/toolbox/restore_st_settings.py), [restore_look_model.py](../source/a7m4/toolbox/restore_look_model.py) |
| Feature jobs and bounded requests | [program_worker.py](../source/a7m4/toolbox/program_worker.py), [resource_worker.py](../source/a7m4/toolbox/resource_worker.py), [native_channel.py](../source/a7m4/toolbox/native_channel.py) |
| Sound preparation, encoding and audition | [pin_audio.py](../source/a7m4/research/pin_audio.py), [native_audio_codec.py](../source/a7m4/research/native_audio_codec.py) |
| Native icon generation and decoded previews | [native_icons.py](../source/a7m4/research/native_icons.py), [looks_resource_scope.py](../source/a7m4/toolbox/looks_resource_scope.py) |
| Temporary workspace budget | [workspace.py](../source/a7m4/toolbox/workspace.py), [native_build.py](../source/a7m4/toolbox/native_build.py) |
| Job exclusivity and owned temporary files | [ownership.py](../source/a7m4/toolbox/ownership.py), [job_ownership.py](../source/a7m4/toolbox/job_ownership.py) |
| Administrator authorization and sessions | [macos_authorization.py](../source/a7m4/toolbox/macos_authorization.py), [macos_session.py](../source/a7m4/toolbox/macos_session.py) |
| Segmented logs and diagnostic export | [run_log.py](../source/a7m4/toolbox/run_log.py), [diagnostics_archive.py](../source/a7m4/toolbox/diagnostics_archive.py) |
| GUI calls and user interaction | [A7M4Product.swift](../source/packaging/internal-research/A7M4Product.swift) |

Each source, license and provenance excerpt is recorded in [source-index.json](source-index.json). Excerpts preserve the original file contents. Historical comments and status labels are not observations of the camera's current state.

## Local preparation

### Portable backups and internal receipts

An `.a7capture` file is a portable archive. The `--capture` and `--original-capture` planning arguments take the `capture.private.json` receipt returned after import or capture; the archive itself is not a substitute.

```sh
./cli/check-backup /absolute/path/original.a7capture
./cli/a7m4-toolbox driver portable-import /absolute/path/original.a7capture \
  --output /absolute/path/new-import-directory
```

The import result's `receipt` field identifies the required receipt. Keep the import directory and its bound materials together; do not rewrite paths or move directories belonging to an active job.

### Freeze the final selection

[FL2/FL3 with silence](../examples/fl23-silent.draft.json) and the [M9 recocking combination](../examples/m9-recock.draft.json) are example drafts. Presets populate controls; execution binds the final controls and assets, not the preset number.

```sh
./cli/a7m4-toolbox driver selected-freeze \
  --draft /absolute/path/fl23-silent.draft.json \
  --original-capture /absolute/path/import/capture.private.json \
  --output /absolute/path/new-selected-config.json

./cli/a7m4-toolbox driver selected-plan \
  --capture /absolute/path/current/capture.private.json \
  --selection /absolute/path/new-selected-config.json \
  --selection-sha256 SELECTION_SHA256_FROM_FREEZE_RESULT \
  --output /absolute/path/new-selected-plan.json
```

Use the `selection_sha256` field returned by freezing, not a hash of the entire JSON file. Supply `--prepared` when selecting sound and `--native-project` when selecting Custom1 names and icons. Asset parameters must agree with the final selection.

### Sounds and icons

```sh
./cli/a7m4-toolbox pin-sound-presets
./cli/a7m4-toolbox pin-sound-prepare --help
./cli/a7m4-toolbox pin-sound-verify --help
./cli/a7m4-toolbox pin-sound-preview --help
./cli/a7m4-toolbox native-icons --help
```

These commands prepare local assets; they do not install them on the camera. Audition audio and icon previews are decoded from their final encoded output. One project binds the name and the normal-list, selected-list and playback icons. The current product deploys Custom1 and retains the other slots' original state.

The convenience presets use a 40 ms recocking gap and a 1/8-second cutoff; the final configuration also offers a 1/50-second candidate. The exposure cutoff, internal KA-SHA spacing and recocking gap are separate controls. The complete asset manifest still determines compatibility; editing a draft alone does not establish it.

## Camera operations and restoration checkpoints

Actual camera commands require explicit confirmation of execution, battery, MSC, backup and risk for that operation. The GUI provides instructions. When using the CLI directly, read the command's `--help` and supply flags only for facts actually confirmed.

The current installation entry point is `driver selected-install`. Restoration from an original backup follows this sequence:

```text
Validate the original backup
→ Capture the fresh current state
→ backup-target-plan
→ backup-target-restore
→ Complete the checkpoint's user action, recapture and resume
→ backup-target-verify
→ backup-target-acceptance
```

The restoration plan uses the current capture and selected original backup, without requiring the previous installation order. It restores supported feature areas, not every backup item or all personal settings.

When ST protection is required, the tool first saves the current creative look and the six custom base looks as ST, then waits for a new boot and proof of the actual interface state. After the first restart, the current look should be ST. Added look options may still appear in the menu; this is not restoration completion.

Each checkpoint requires a subsequent new boot, a fresh capture and matching body and original-backup checks. A checkbox or USB reconnection is not a substitute. CLI continuation takes `--previous-job` pointing to a safe checkpoint and `--startup-confirmed` only after the actual restart. Use a new output directory for each round and retain earlier job directories for evidence verification.

The number of restoration rounds depends on live conditions. Perform a cold start only after the tool confirms a safe exit and explicitly requests it: disconnect USB-C → switch OFF → wait about 15 seconds; if the red light next to the trash-can icon remains lit, wait until it goes out → remove the battery → wait 30 seconds → reinsert it and turn the camera on → reconnect and enter MSC.

Post-startup machine verification is not final completion. The user must still check names and icons, sound, actual shooting and playback before saving final acceptance. If the result is unknown or exit is unconfirmed, preserve the state and export diagnostics rather than retrying directly.

## Check scope and records

The current file capture covers 11 objects and retains required settings and identity materials. Language resources are limited to the horizontal and vertical English, Simplified Chinese and Traditional Chinese sets. Older 73-object archives can still be validated locally; device operations use the current supported scope.

C means the specific feature scope for this operation; D means the dependencies needed to handle it safely. Unrelated E/F differences may be recorded and do not independently block execution merely because they differ from an old backup. Input structure, necessary dependencies and exit conditions must still be verified.

Workspace budgeting uses measured capacity, with every upload strictly below 65536 B and at least 8 MiB reserved. Complete host reads and the camera's small-packet workspace are different constraints. An additional 1 GiB of host log space is recommended; a space warning cannot guarantee later saves will succeed.

Run `export-logs` as the current user, not under blanket sudo. stdout carries structured results and stderr carries diagnostics; they are saved separately. Process exit alone does not prove that a camera job is complete.

Other historical entry points and comments remain in the source for study. They are not the recommended GUI workflow; this guide uses `selected-*` and `backup-target-*`.
