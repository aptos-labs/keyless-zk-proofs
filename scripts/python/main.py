import os
import sys

import utils
from utils import eprint
import prover_service
import circuit
import setup
import setup.testing_setup
import misc




def print_usage(unused=[]):
    eprint("""
Usage:
   task.sh <one or more setup actions> : run the given setup actions
   task.sh -h                          : print this screen

   (if no actions are provided, default is "setup-dev-environment")

   Any of the actions below should be referenced as <parent>:<child>. So for example, to install
   the prover service deps, "prover-service:install-deps".

   Current actions:
   --------------

   - prover-service: 

      - install-deps: install the dependencies for building and running the prover service.

      - add-envvars-to-profile: Add the directory containing libtbb to LD_LIBRARY_PATH. Required
        for running the prover service and for running the prover service tests.

   - circuit:

      - install-deps: install the dependencies required for compiling the circuit and building
        witness-generation binaries.


   - setup:

      - download-latest-setup: downloads latest trusted setup and installs it in RESOURCES_DIR. If
        RESOURCES_DIR is not set, uses the default location "~/.local/share/aptos-prover-service".

      - run-dummy-setup: UNIMPLEMENTED Compiles the circuit in this repo and runs a dummy *untrusted* 
        setup based on the result of that compilation. Installs it in RESOURCES_DIR? Is it bad that 
        it will overwrite any existing setup downloaded using setup:download-latest-setup?

   - misc:

      - compute-sample-proof: UNIMPLEMENTED

      - install-circom-precommit-hook: Installs a pre-commit hook that requires the main circuit to 
        compile before committing.

   - setup-dev-environment: runs the following tasks:
      - prover-service:install-deps
      - prover-service:add-envvars-to-profile
      - circuit:install-deps
      - setup:download-latest-setup
      - setup:download-latest-witness-gen-c
      - setup:download-latest-witness-gen-wasm

""")


def setup_dev_environment():
    handle_action("prover-service:install-deps")
    handle_action("prover-service:add-envvars-to-profile")
    handle_action("circuit:install-deps")
    handle_action("setup:download-latest-setup")
    handle_action("setup:download-latest-witness-gen-c")
    handle_action("setup:download-latest-witness-gen-wasm")


def action_not_recognized(action):
    eprint("Action '" + action + "' not recognized.")
    print_usage()
    exit(1)


def handle_action(action):
    action_parts = action.split(':')
    action_category = action_parts[0]
    action_body = ":".join(action_parts[1:])

    
    if action_category == "prover-service":
        if action_body == "install-deps":
            prover_service.install_deps()
        elif action_body == "add-envvars-to-profile":
            prover_service.add_envvars_to_profile()
        else:
            action_not_recognized(action)


    elif action_category == "circuit":
        if action_body == "install-deps":
            circuit.install_deps()
        else:
            action_not_recognized(action)


    elif action_category == "setup":
        if action_body == "download-latest-setup":
            release_old = os.environ.get('RELEASE_OLD')
            release_new = os.environ.get('RELEASE_NEW')
            witness_gen = os.environ.get('WITNESS_GEN')
            setup.download_ceremonies_for_releases(release_old, release_new, witness_gen)
        elif action_body == "procure-testing-setup":
            ignore_cache = os.environ.get('IGNORE_CACHE')
            setup.testing_setup.procure_testing_setup(ignore_cache)
        else:
            action_not_recognized(action)


    elif action_category == "misc":
        if action_body == "compute-sample-proof":
            misc.compute_sample_proof()
        elif action_body == "install-circom-precommit-hook":
            misc.install_circom_precommit_hook()
        else:
            action_not_recognized(action)

    elif action_category == "setup-dev-environment":
        setup_dev_environment()
    elif action_category == "-h":
        print_usage()
    else:
        action_not_recognized(action)



if len(sys.argv) == 1:
    setup_dev_environment()

for action in sys.argv[1:]:
    handle_action(action)

utils.remind_to_restart_shell_if_needed()

