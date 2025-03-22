from utils import manage_deps
import typer

app = typer.Typer(no_args_is_help=True)

@app.command()
def install_deps():
    """Install the dependencies required for compiling the circuit and building witness-generation binaries."""
    manage_deps.install_deps(["node", "circom", "snarkjs", "circomlib", "nlohmann-json"])
