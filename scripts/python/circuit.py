from utils import manage_deps

def install_deps():
    manage_deps.install_deps(["node", "circom", "snarkjs", "circomlib"])
