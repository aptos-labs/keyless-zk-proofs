import os
import sys

import utils
import prover_service
import circuit
import trusted_setup
import misc




def print_usage(unused=[]):
    print("""
Usage:
   setup_environment.sh <one or more setup actions> : run the given setup actions
   setup_environment.sh -h                        : print this screen

   (if no actions are provided, default is "all")

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


   - trusted-setup:

      - download-latest: downloads latest trusted setup and installs it in RESOURCES_DIR.

      - run-dummy-setup: Compiles the circuit in this repo and runs a dummy *untrusted* setup 
        based on the result of that compilation. Installs it in RESOURCES_DIR? What about 

   - misc:
      - compute-sample-proof

   - setup-dev-environment: runs the following tasks:
      - prover-service:install-deps
      - prover-service:add-envvars-to-profile
      - circuit:install-deps
      - trusted-setup:download-latest
""", file=sys.stderr)





prover_service_handlers = {
        "install-deps": prover_service.install_deps,
        "add-envvars-to-profile": prover_service.add_envvars_to_profile
        }


cicuit_handlers = {
        "install-deps": circuit.install_deps,
        }

trusted_setup_handlers = {
        "download-latest": trusted_setup.download_latest,
        "run-dummy-setup": trusted_setup.run_dummy_setup
        }

misc_handlers = {
        "compute-sample-proof": misc.compute_sample_proof
        }





def handle_prover_service_action(action):
    if action not in prover_service_handlers:
        action_not_recognized("prover-service:" + action)
    else:
        prover_service_handlers[action]()


def handle_circuit_action(action):
    if action not in circuit_handlers:
        action_not_recognized("circuit:" + action)
    else:
        circuit_handlers[action]()


def handle_trusted_setup_action(action):
    if action not in trusted_setup_handlers:
        action_not_recognized("trusted-setup:" + action)
    else:
        trusted_setup_handlers[action]()

def handle_misc_action(action):
    if action not in misc_handlers:
        action_not_recognized("trusted-setup:" + action)
    else:
        misc_handlers[action]()


handlers = { 
            "prover-service": handle_prover_service_action,
            "circuit": handle_circuit_action,
            "trusted-setup": handle_trusted_setup_action,
            "misc": handle_misc_action,
            "-h": print_usage
            }


def handle_setup_dev_env_action():
    handle_action("prover-service:install-deps")
    handle_action("prover-service:add-envvars-to-profile")
    handle_action("circuit:install-deps")
    handle_action("trusted-setup:download-latest")


def action_not_recognized(action):
    print("Action '" + action + "' not recognized.", file=sys.stderr)
    print_usage()
    exit(1)


def handle_action(action):
    action_parts = action.split(':')
    action_category = action_parts[0]
    action_body = ":".join(action_parts[1:])

    if action_category not in handlers:
        action_not_recognized(action)
    else:
        handlers[action_category](action_body)




if len(sys.argv) == 1:
    handle_setup_dev_env_action()

for action in sys.argv[1:]:
    handle_action(action)

utils.remind_to_restart_shell_if_needed()

