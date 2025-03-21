
This directory contains scripts that define various actions for this repo.
The main "entrypoint" is `task.sh`.

To see usage, run `task.sh --help`:

```bash

./task.sh --help

 Usage: main.py [OPTIONS] COMMAND [ARGS]...

╭─ Options ──────────────────────────────────────────────────────────────────────────────────╮
│ --install-completion          Install completion for the current shell.                    │
│ --show-completion             Show completion for the current shell, to copy it or         │
│                               customize the installation.                                  │
│ --help                        Show this message and exit.                                  │
╰────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ─────────────────────────────────────────────────────────────────────────────────╮
│ setup-dev-environment   Installs dependencies for the prover service and circuit, and      │
│                         procures a testing setup. Equivalent to running:                   │
│ prover-service          Commands related to the prover service.                            │
│ setup                   Commands related to managing the circuit setup.                    │
│ circuit                 Commands related to managing the circuit setup.                    │
│ misc                    Miscellaneous commands that don't fit anywhere else.               │
╰────────────────────────────────────────────────────────────────────────────────────────────╯
```

For each command group, it is possible to see the commands in that group as
follows: (example with `setup`)

```bash

./task.sh setup --help

`` Usage: main.py setup [OPTIONS] COMMAND [ARGS]...

 Commands related to managing the circuit setup.

╭─ Options ──────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                │
╰────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ─────────────────────────────────────────────────────────────────────────────────╮
│ download-ceremonies-for-releases   Download two ceremonies corresponding to default and    │
│                                    new in the prover service, installing in RESOURCES_DIR. │
│                                    If RESOURCES_DIR is not set, uses the default location  │
│                                    ~/.local/share/aptos-keyless.                           │
│ procure-testing-setup              Procure a (untrusted) setup corresponding to the        │
│                                    current circuit in this repo for testing purposes.      │
╰────────────────────────────────────────────────────────────────────────────────────────────╯
```

And then again to see the detailed description of a specific command:

```bash
./task.sh setup procure-testing-setup --help

 Usage: main.py setup procure-testing-setup [OPTIONS]

 Procure a (untrusted) setup corresponding to the current circuit in this repo for testing
 purposes.
 Specifically, does the following:

  • Computes a hash of the circuit currently in the repo.
  • Note that currently this hash is computed from the circuit source code, not the R1CS
    file. This is because compiling the circuit itself takes a minute, and I don't want to
    wait one minute just to obtain an identifier for the circuit
  • Checks a google cloud storage GCS bucket (refer to this as the "cache" from now on)
    whether there is already a setup for this circuit.
  • If present in the cache, downloads it.
  • If the downloaded setup was built on an arm machine, it won't contain the C witness gen
    binaries. If the local machine is an x86-64 machine and the downloaded setup does not
    contain them, the script will build these C binaries and re-upload the setup.
  • If not present, compiles the circuit and witness gen binaries and runs a local (1-person)
    setup.
  • Installs the setup in the correct location, so that running cargo test -p prover-service
    will use this setup.
  • Uploads the setup to the cloud.


                                            Note:

 Right now, the GCS bucket requires being authenticated to GC with an Aptos account to use,
 since Stelian has not yet provided us with a bucket that allows for unauthenticated read
 access. So if you try to run this action without running gcloud auth login --update-adc, the
 script builds the setup locally and does not upload to the cache.

╭─ Options ──────────────────────────────────────────────────────────────────────────────────╮
│ --ignore-cache        TEXT  Build the setup from scratch regardless of whether it exists   │
│                             in the GCS cache.                                              │
│                             [default: False]                                               │
│ --help                      Show this message and exit.                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────╯
```



## Resources directory structure

The commands in `./task.sh setup` install circuit setups in a folder
called the "resources" directory. By default this is
`~/.local/share/aptos-keyless`, but it can be changed by setting the
environment variable `RESOURCES_DIR`. Its structure is as follows:

- `./ceremonies`: Contains downloaded ceremonies. Each subdirectory in this
  directory is named according to the release tag name.
- `./testing_setups`: Contains testing setups. Each subdirectory in this
  directory is named according to the circuit hash corresponding to the
  setup.
- `./current_setups`: Contains two softlinks `default` and `new`, which
  each link to one of the setups in `ceremonies` or `testing_setups`. These
  specify the setups that the prover service will use when running tests or
  deploying locally.
- `./powersOfTau28_hez_final_21.ptau`: the powers-of-tau file which is used
  to build testing setups. (Downloaded automatically on the first run of
  `task.sh setup procure-testing-setup`.)


