import os
import sys

import utils
from utils import eprint
import prover_service
import circuit
import setups
import setups.testing_setup
import misc
#from invoke import Program, Executor, Context, Collection, task
import typer

app = typer.Typer(no_args_is_help=True)
app.add_typer(prover_service.app, name="prover-service", help="Commands related to the prover service.")
app.add_typer(setups.app, name="setup", help="Commands related to managing the circuit setup.")
app.add_typer(circuit.app, name="circuit", help="Commands related to managing the circuit setup.")
app.add_typer(misc.app, name="misc", help="Miscellaneous commands that don't fit anywhere else.")



@app.command()
def setup_dev_environment(c):
    """Runs the following tasks: prover-service:install-deps, prover-service:add-envvars-to-profile, circuit:install-deps, and setup:procure-testing-setup.
    """
    prover_service.install_deps()
    prover_service.add_envvars_to_profile()
    circuit.install_deps()
    setups.testing_setup.procure_testing_setup(ignore_cache=False)




app()

utils.remind_to_restart_shell_if_needed()

