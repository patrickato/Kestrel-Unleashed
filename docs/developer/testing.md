# Running the tests

The on-device `kestrel_pi` package (the plugin host, the web dashboard and
the learning agent) ships with a `pytest` suite. It is the fast feedback loop
for the application code — no image build, no hardware, no radio.

## `make test`

```bash
make test
# = cd builder/extra/files/kestrel_pi && python3 -m pytest -q
```

It runs against the package in the source tree, so you run it on the build host,
not inside the image.

**Dependencies.** The package declares no runtime dependencies of its own (the
image's `pi` venv provides them), so the tests need a few libraries present in
the environment you run them in:

- `flask` and `requests` — the web/daemon tests. Missing `flask` skips the web
  suite (`importorskip`).
- `numpy` — the agent `spec`/`metrics`/`readout` tests (a hard import for those).
- The heavy ML stack (`gymnasium`, `stable-baselines3`, `sb3-contrib`, and
  therefore `torch`) — only the Gymnasium-env, policy and training-shape tests.
  These `importorskip` the stack, so on a host without it they **skip** rather
  than fail. A handful of expected skips is normal; it is not a broken run.

In a cloud Claude Code session, `.claude/hooks/session-start.sh` installs the
lint tools but not these; `pip install flask requests numpy` (into the same
interpreter) gets most of the suite running, and installing the ML stack is only
worth it when you are changing the agent env/policies.

## CI runs these

Two workflows run on every push/PR: **Lint** (`make lint` — `ansible-playbook
--syntax-check`, `yamllint`, `shellcheck`, and a `py_compile` byte-compile of the
package) and **Test** (`.github/workflows/test.yml`, which runs `make test` —
the `pytest` suite). A green PR means both passed. Still run `make test` yourself
while iterating under `builder/extra/files/kestrel_pi/` so you catch failures
before the push.

## Layout and coverage

Tests live in `builder/extra/files/kestrel_pi/tests/` as `test_*.py` and are
excluded from the built package (`pyproject.toml` `exclude = ["tests*"]`), so
nothing test-only ships in the image. They cover, roughly:

- **Daemon / plugin framework** — `test_daemon`, `test_loader`, `test_dispatch`,
  `test_context`, `test_options`, `test_ui`, `test_reference_plugins`.
- **Web + privileged helpers** — `test_web`, `test_plugins_apply`.
- **Capture + config tooling** — `test_capture`, `test_config_set`,
  `test_connectivity`.
- **Learning agent** — `test_agent_spec`, `test_agent_env`,
  `test_agent_policies`, `test_agent_metrics`, `test_agent_readout`,
  `test_agent_training`, `test_agent_train_reward`.
- **In-place updates** — `test_updates`, `test_update_apply`.

## Adding a test

Drop a `test_*.py` into `tests/`. Keep it pure stdlib plus the libraries above;
`importorskip` anything heavy (the ML stack, or `flask` if you somehow test
without it) so the suite still runs where that dependency is absent. Keep the
target at **Python 3.11** (the image's interpreter) — no 3.12+ syntax, the same
rule as the package itself.

See also: [Architecture](architecture.md), [Tech stack](tech-stack.md),
[Plugin development](plugin-development.md).
