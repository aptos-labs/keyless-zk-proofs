import utils
import json
import typer
import tempfile
import contextlib
from pathlib import Path
from typing import Optional

app = typer.Typer(no_args_is_help=True)

@app.command()
def install_deps():
    """Install the dependencies required for compiling the circuit and building witness-generation binaries."""
    utils.manage_deps.install_deps(["node", "circom", "snarkjs", "circomlib", "nlohmann-json", "nasm"])

# TODO: Do we want to make the compilation here and the one in testing_setups.py both work via a common
# utility function that calls circom. Otherwise, we may have disagreement on the optimizations enabled,
# the circom libraries used, etc.?
@app.command()
def compile(
    circom_file_path: Optional[Path] = typer.Option(
        None, "--circom-file-path", "-c", help="Path to the circom file to be compiled"
    ),
    o: bool = typer.Option(
        False, "--optimized", "-o", help="Enables optimization passes (--O2) for compiling the circuit to a smaller R1CS"
    ),
):
    """Compiles the circuit to R1CS, creating a main.r1cs, main_constraints.json, and main.sym file next to main.circom. Useful for testing."""
    templates_dir = utils.repo_root() / "circuit/templates"

    if circom_file_path is None:
        circom_file_path = templates_dir / "main.circom"
        typer.echo(f"No circom file path provided. Defaulting to main.circom.")

    oFlag = "--O0"
    if o == True:
        oFlag = "--O2"

    typer.echo(f"Compiling {circom_file_path}...")
    typer.echo()

    circom_cmd = f"circom {oFlag} -l {templates_dir} -l $(. ~/.nvm/nvm.sh; npm root -g) {circom_file_path} --r1cs --json --sym"

    typer.echo("Compiling via:")
    typer.echo(f" {circom_cmd}")
    typer.echo()
    utils.run_shell_command(f"time {circom_cmd}")


@app.command()
def count_r1cs_nonzero_terms(
    constraints_json_path: Optional[Path] = typer.Option(
        None, "--json", "-j", help="Optional path to main_constraints.json")
):
    """
    Counts the number of nonzero constraints in each of the R1CS matrices.

    If `constraints_path` is given, loads constraints from that file.
    Otherwise, compiles the circuit in a temporary directory.
    """
    def load_and_count(path: str):
        a_nonzero = b_nonzero = c_nonzero = 0
        union_nonzero = 0
        max_nonzero = 0

        with open(path) as f:
            constraints = json.load(f)["constraints"]
            for [a, b, c] in constraints:
                a_nonzero += len(a)
                b_nonzero += len(b)
                c_nonzero += len(c)
                union_nonzero += len(a | b | c)
                max_nonzero += max(len(a), len(b), len(c))

        total_nonzero = a_nonzero + b_nonzero + c_nonzero

        print("")
        print(f"The matrix A has {a_nonzero:,} nonzero terms.")
        print(f"The matrix B has {b_nonzero:,} nonzero terms.")
        print(f"The matrix C has {c_nonzero:,} nonzero terms.")
        print("-------------------------------------------------")
        print(f"nonzero(A) + nonzero(B) + nonzero(C): {total_nonzero:,} .")
        print(f"nonzero(r_1 A + r_2 B + r_3 C): {union_nonzero:,} .")
        print(f"Row-wise max of nonzero terms count: {max_nonzero:,} .")

    if constraints_json_path:
        load_and_count(constraints_json_path)
    else:
        with tempfile.TemporaryDirectory() as temp_dir:
            with contextlib.chdir(temp_dir):
                compile(o=True, circom_file_path=None)
                load_and_count("main_constraints.json")

