<!-- SPDX-License-Identifier: GPL-3.0-or-later
     Copyright (C) 2026 Pau Aliagas -->

# Threat model

## What it is and where it runs

mod-host is an LV2 plugin host for JACK. It runs as a daemon (`src/mod-host.c`), or inside a JACK server
as an internal client (`jack_initialize()` in the same file), and is driven by text commands over TCP.

- **Command port:** TCP, default 5555 (`SOCKET_DEFAULT_PORT`, `src/mod-host.h`), `-p` to change it.
- **Feedback port:** off by default for the daemon (`-f` turns it on); the internal client opens it at
  command port + 1. The daemon only writes to it; `socket_run()` never reads from it.
- **Bind address:** loopback. `g_bind_address = INADDR_LOOPBACK` in `src/socket.c`. `-b <IPv4>` or
  `MOD_DEVICE_HOST_BIND_ADDRESS` (internal client) change it; `0.0.0.0` listens on every interface.
  IPv4 only. Both ports share the one address.
- **Connections:** one controller at a time. `socket_run()` accepts one client, serves it until it
  disconnects, then accepts the next. There is no authentication of any kind.
- **Threads:** each plugin gets its own JACK client and process callback (`ProcessPlugin`,
  `src/effects.c`), which runs in the JACK real-time thread. Plugins are told, as LV2 options, to run
  their own threads `SCHED_FIFO` one below JACK's priority (`MOD_PLUGIN_THREAD_PRIORITY` overrides it).
- **User:** whoever starts it. `packaging/mod-host.service` is installed both as a system unit and as a
  user unit (`packaging/mod-host.spec`). The system unit sets no `User=`, so started that way it runs as
  root. The unit passes neither `-b` nor `-f`, so it listens on 127.0.0.1:5555 only.

## Inputs

| Input | Read by | Who can write it | Trusted |
| --- | --- | --- | --- |
| Command text on the command port | `socket_run()`, `protocol_parse()`, `src/host-dispatch.c`, `src/mod-host.c` | any local process of any user (loopback TCP checks no uid); the LAN or beyond with `-b` other than loopback | untrusted, but see trust boundary |
| Paths in commands: `bundle_add`, `bundle_remove`, `state_load`, `state_save`, `state_tmpdir`, `preset_save`, `load`, `save` | `effects_bundle_add()`, `effects_state_*()`, `effects_preset_save()`, `load_cb()`, `save_cb()` | whoever reaches the command port | untrusted |
| URIs in commands: `add`, `preset_load`, `preset_show`, `patch_set` values (including `atom:Path`) | lilv, `effects_set_property()` | whoever reaches the command port | untrusted |
| `monitor <host> <port> 1` | `monitor_start()`, `src/monitor.c`: opens an outbound TCP connection | whoever reaches the command port | untrusted |
| LV2 bundles: Turtle metadata and plugin/UI shared objects | `lilv_world_load_all()` (`LV2_PATH`, lilv's default dirs, including the user's `~/.lv2`), `lilv_world_load_bundle()`, `dlopen()` for external UIs | plugin authors; anyone who can write to an LV2 path or name a bundle with `bundle_add` | trusted code once loaded; the metadata is parsed by lilv/serd |
| Plugin state and preset files (`.ttl`, plugin-written files) | lilv `lilv_state_*`, plugin `make_path` via `MakePluginStatePath()` (`src/state-paths.c`) | the user, the controller, the plugin itself | untrusted data, read by lilv and by the plugin |
| Licence key files | `MOD_KEYS_PATH` + SHA-1 of the licence URI (`src/effects.c`), at most 5 MiB | the local user | trusted |
| MIDI and audio on JACK ports | process callbacks, MIDI learn / CC maps | any JACK client of the same server | untrusted data |
| HMI shared memory `/sys_msgs` | `sys_serial_open()` (`src/sys_host.h`), internal-client mode only | processes of the same user | trusted |
| Command-line options and environment (`MOD_LOG`, `MOD_PLUGIN_THREAD_PRIORITY`, `MOD_KEYS_PATH`, `MOD_DEVICE_HOST_PORT`, `MOD_DEVICE_HOST_BIND_ADDRESS`, `LV2_PATH`) | `main()`, `jack_initialize()`, `effects_init()` | whoever starts the process | trusted |

## Trust boundary

The command port is a full-privilege control channel. A client can name any bundle directory with
`bundle_add` and then `add` one of its plugins, which loads and runs that shared object as the daemon's
user; it can read any file the daemon can read (`load`, in readline builds), write files where the
daemon can write (`save`, `state_save`, `preset_save`), and make the daemon open TCP connections
(`monitor`). Anyone who can connect therefore has the daemon's privileges. On loopback that is every
local user, not only the daemon's own user. Binding to any address other than loopback hands the same
power to the network. Plugins are trusted native code running in the same process as the host.

## What the code assumes and enforces

- **Framing** (`socket_run()`, `src/socket.c`): commands end with a NUL byte. The receive buffer starts
  at 1024 bytes (`SOCKET_MSG_BUFFER_SIZE`) and doubles as needed; a command reaching 16 MiB
  (`SOCKET_MSG_MAX_SIZE`, `src/socket.h`) closes the connection. An unterminated last command is run when
  the client disconnects. `SO_REUSEADDR` only, never `SO_REUSEPORT`, so a second daemon cannot listen on
  the same port (`tests/bind-test.c`, `tests/bind-sabotage.sh`).
- **Parsing** (`protocol_parse()`, `src/protocol.c`; `strarr_split()`, `src/utils.c`): splits on spaces,
  with double quotes and `\"` (`ENABLE_QUOTATION_MARKS`). It checks the verb and the word count only and
  answers `not found`, `few arguments` or `many arguments`. Argument types are not checked (a `TODO` in
  the code): `%i` and `%f` are read with `atoi()`/`atof()`, so a non-number becomes 0 and out-of-range
  values are not refused.
- **Instance ids:** `INSTANCE_IS_VALID()` / `InstanceExist()` (`src/effects.c`) bound every id to
  `0..MAX_INSTANCES-1` before indexing `g_effects`; a bad id answers a negative code.
- **Parameter values:** `effects_set_parameter()` clamps to the port's minimum and maximum. A NaN value
  (`atof("nan")`) is not refused, since it fails both comparisons.
- **Paths:** not enforced. `bundle_add` and `bundle_remove` only `realpath()` their argument; the state,
  preset, `load` and `save` paths are used as given. `MakePluginStatePath()` joins the state directory,
  `effect-<n>` and the path the plugin asks for, creating directories with mode 0755. It refuses (NULL,
  nothing created) a request that is empty, absolute or has a `..` component, so the result stays inside
  `effect-<n>`; subdirectories below it are allowed, as LV2's `make_path` allows them
  (`tests/state-paths-test.c`). A symbolic link a plugin made inside its own directory is still followed.
- **Fixed PID file:** without `-n`/`-v`/`-i` the parent writes `/tmp/mod-host.pid` with `fopen("w")`
  (`PID_FILE`, `src/mod-host.c`), a predictable name in a shared directory.
- **Replies:** `resp <n>`, where a negative `n` is an error from `src/host-errors.h`: instance errors
  -1..-4 (invalid, already exists, does not exist, unlicensed), plugin/LV2 errors -101..-105 (URI,
  instantiation, parameter symbol, preset URI, state), JACK errors -201..-207, assignment errors
  -301..-305, unavailable features -401..-404, -901 memory allocation, -902 invalid operation (also the
  answer for a verb the backend does not provide, `src/host-dispatch.c`).

## Fuzz coverage

The harnesses are libFuzzer with AddressSanitizer and UndefinedBehaviorSanitizer (`fuzz/README.md`,
`Makefile`); CI runs each for 60 s over `fuzz/corpus/` (`.github/workflows/ci.yml`).

| Untrusted input | Harness |
| --- | --- |
| Command text: word splitting and pattern matching | `fuzz/fuzz_protocol.c` |
| Command text: every verb's argument handling and reply | `fuzz/fuzz_dispatch.c` (over a fake backend; `fuzz/socket_fuzz.c` replaces `src/socket.c`) |
| Plugin-requested state paths | `fuzz/fuzz_statepaths.c` (`MakePluginStatePath()`, `GetPluginStateDir()`) |
| Scenario files (a test tool's input, not the daemon's) | `fuzz/fuzz_scenario.c` |

### Gaps

- The socket framing in `socket_run()` is not fuzzed; `fuzz/socket_fuzz.c` stands in for it. It has unit
  tests in `tests/socket-test.c`.
- The real backend in `src/effects.c` (instances, parameters, `patch_set` atom building, state, presets,
  MIDI maps) is not fuzzed; `fuzz_dispatch` uses a fake.
- LV2 Turtle metadata, presets and state files are parsed by lilv/serd and are not fuzzed here.
- MIDI and audio arriving on JACK ports are not fuzzed.
- `fuzz_statepaths` checks that the joined path is exact and that a request leaving the instance's
  directory is refused; it does not follow symbolic links.
- No authentication on the command port, no path allow-list, no check on numeric arguments.

## Reporting

Report a vulnerability privately through this repository's Security tab ("Report a vulnerability"). Issues
in code inherited unchanged from upstream mod-host also belong upstream.
The policy is the organisation's `SECURITY.md`.
