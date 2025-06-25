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

# Scripts now use the typer library, which automatically builds usage strings for 
# each command using the corresponding python function's docstring.


app = typer.Typer(name="task.sh", no_args_is_help=True, rich_markup_mode="markdown")
app.add_typer(prover_service.app, name="prover-service", help="Commands related to the prover service.")
app.add_typer(setups.app, name="setup", help="Commands related to managing the circuit setup.")
app.add_typer(circuit.app, name="circuit", help="Commands related to managing the circuit setup.")
app.add_typer(misc.app, name="misc", help="Miscellaneous commands that don't fit anywhere else.")



# Adding lots of space in the docstring here b/c typer needs at least two newlines in the docstring in order to print a newline...
@app.command()
def setup_dev_environment():
    """
    Installs dependencies for the prover service and circuit, and procures a testing setup. Equivalent to running:

    ```

    ./scripts/task.sh prover-service install-deps

    ./scripts/task.sh prover-service add-envvars-to-profile

    ./scripts/task.sh circuit install-deps

    ./scripts/task.sh setup procure-testing-setup

    ```
    """
    prover_service.install_deps()
    prover_service.add_envvars_to_profile()
    circuit.install_deps()




app(prog_name='task.sh')

utils.remind_to_restart_shell_if_needed()

