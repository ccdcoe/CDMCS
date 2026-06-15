# Alkeme — a terminal UI for Arkime

[Alkeme](https://arkime.com/alkeme) ([source on GitHub](https://github.com/arkime/alkeme)) is a
keyboard-driven **terminal UI client for the Arkime viewer**, written in Rust. It talks to the
same viewer HTTP API the web UI uses, so it is a fast, mouse-free way to browse sessions, SPI
data and Cont3xt over SSH — handy when you only have a terminal to the box.

* Homepage: <https://arkime.com/alkeme>
* GitHub: <https://github.com/arkime/alkeme> (releases, source, issues)

## Install (prebuilt binary)

Alkeme ships as a single static binary on the [GitHub releases](https://github.com/arkime/alkeme/releases)
page — **no Rust toolchain / `cargo` build needed**:

```bash
ALKEME_VERSION="0.5.0"
sudo wget -O /usr/local/bin/alkeme \
  "https://github.com/arkime/alkeme/releases/download/v${ALKEME_VERSION}/alkeme-linux-x86_64"
sudo chmod +x /usr/local/bin/alkeme
```

(The `singlehost` provisioner installs this automatically and adds an `arkime-tui` wrapper that
opens the local viewer with the course credentials.)

## Usage

Point it at a viewer URL and pass the viewer credentials:

```bash
alkeme http://localhost:8005 --auth digest --user vagrant:vagrant
```

Run `alkeme --help` for the full flag list (auth modes, `--search` / `--viewer-search` to start
with an expression, `--viewer-time-range`, Cont3xt options, an encrypted cookie `--jar`, …).

### Keybindings

| Key | Action |
|-----|--------|
| `Tab` / `Shift+Tab` | switch tabs |
| `j` / `k` | navigate up/down |
| `Enter` | open detail |
| `Esc` | close overlay |
| `t` / `T` | cycle time range |
| `/` | expression search |
| `r` | refresh |
| `q` | quit |

## Time range — and replacing it with `starttime` / `stoptime`

The `t` / `T` key only **cycles preset, relative ranges** (`15m, 30m, 1h, 6h, 24h, 1w, 2w, 1M,
All`); `--viewer-time-range` takes the same presets plus relative durations like `72h`, `2w`,
`3m`. There is **no absolute calendar picker** — so to scope to *one specific day or window*,
filter on time **in the expression** instead, using two indexed fields:

| Field | Maps to | Meaning |
|-------|---------|---------|
| `starttime` | `firstPacket` | session start |
| `stoptime` | `lastPacket` | session end |

Example — **only 22 April 2026**:

```
starttime >= "2026-04-22 00:00:00" && starttime < "2026-04-23 00:00:00"
```

In Alkeme:

1. Press `t` / `T` until the range is **`All`** — otherwise the relative window won't cover the
   target date and you'll get zero results.
2. Press `/` and enter the expression above.

…or launch straight into it:

```bash
alkeme --viewer-time-range All \
  --viewer-search 'starttime >= "2026-04-22 00:00:00" && starttime < "2026-04-23 00:00:00"'
```

It combines with any other filter, e.g. `… && protocol == dns` or `… && port.dst == 443`.

### Time format and timezone (what it depends on)

The value is a **quoted date string**. These all parse:

* `"2026-04-22 00:00:00"`  ← recommended (ISO-ish, dashes + explicit time)
* `"2026/04/22 00:00:00"`  (slashes, with time)
* `"2026-04-22T00:00:00"`  (ISO `T`)
* `"2026-04-22"`  (date only — **dashes only**)

Gotchas:

* `"2026/04/22"` (slashes **without** a time) does **not** parse → matches nothing. Prefer the
  dash form and always include the time for day boundaries.
* A bare epoch number (`starttime > 1745280000`) is unreliable — use the quoted string.
* **Timezone:** the string is interpreted in the **Arkime viewer server's timezone**, not your
  laptop's. On the course `singlehost` / capture boxes that is **UTC** (`Etc/UTC`), so
  `"2026-04-22 00:00:00"` means 00:00 **UTC**. Check the box with `timedatectl` (or `date`) if
  in doubt; if the server were e.g. UTC+3 the day boundary would shift by 3h.
