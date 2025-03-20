from utils import manage_deps
from invoke import task

@task
def install_deps(c):
    """Install the dependencies required for compiling the circuit and building witness-generation binaries."""
    manage_deps.install_deps(["node", "circom", "snarkjs", "circomlib", "nlohmann-json"])
