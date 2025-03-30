import utils
import typer
from pathlib import Path
from typing import Optional

app = typer.Typer(no_args_is_help=True)

@app.command()
def install_deps():
    """Install the dependencies required for compiling the circuit and building witness-generation binaries."""
    utils.manage_deps.install_deps(["node", "circom", "snarkjs", "circomlib", "nlohmann-json"])

# TODO: Do we want to make the compilation here and the one in testing_setups.py both work via a common
# utility function that calls circom. Otherwise, we may have disagreement on the optimizations enabled,
# the circom libraries used, etc.?
@app.command()
def compile(
    circom_file_path: Optional[Path] = typer.Option(
        None, "--circom-file-path", "-c", help="Path to the circom file to be compiled"
    ),
    o0: bool = typer.Option(
        False, "--no-optimizations", "-o0", help="Disables optimizations for faster compilation"
    ),
):
    """Compiles the circuit to R1CS, creating a main.r1cs file next to main.circom. Useful for testing."""
    templates_dir = utils.repo_root() / "circuit/templates"

    if circom_file_path is None:
        circom_file_path = templates_dir / "main.circom"
        typer.echo(f"No circom file path provided. Defaulting to main.circom.")

    o0flag = ""
    if o0 == True:
        o0flag = "--O0"

    typer.echo(f"Compiling {circom_file_path}...")
    typer.echo()

    circom_cmd = f"circom {o0flag} -l {templates_dir} -l $(. ~/.nvm/nvm.sh; npm root -g) {circom_file_path} --r1cs"

    typer.echo("Compiling via:")
    typer.echo(f" {circom_cmd}")
    typer.echo()
    utils.run_shell_command(f"time {circom_cmd}")
