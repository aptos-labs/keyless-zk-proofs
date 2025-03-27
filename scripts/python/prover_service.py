from utils import manage_deps
import utils
import typer
import os

app = typer.Typer(no_args_is_help=True)

@app.command()
def install_deps():
    """install the dependencies for building and running the prover service."""
    manage_deps.install_deps(["pkg-config", "lld", "meson", "rust", "clang", "cmake", "make", "libyaml", "nasm", "gmp", "openssl"])
    
@app.command()
def add_envvars_to_profile():
    """Add the directory containing libtbb to LD_LIBRARY_PATH. Required for running the prover service and for running the prover service tests."""
    path = utils.repo_root() / "rust-rapidsnark/rapidsnark/build/subprojects/oneTBB-2022.0.0"
    utils.add_envvar_to_profile("LD_LIBRARY_PATH", "$LD_LIBRARY_PATH:" + str(path))
    utils.add_envvar_to_profile("DYLD_LIBRARY_PATH", "$DYLD_LIBRARY_PATH:" + str(path))

@app.command()
def test_docker_image(release):
    """Run automated docker image test. Expects the prover service docker image to be tagged "prover-service"."""
    os.chdir(utils.repo_root())
    utils.run_shell_command("docker image rm -f automated-docker-test-mock-on-chain || true ", as_root=True)
    utils.run_shell_command("docker image rm -f automated-docker-test-test-runner || true ", as_root=True)
    utils.run_shell_command(f"cd automated-docker-test && cargo run prepare-test \"{release}\" \"{release}\"")
    utils.run_shell_command("docker compose -f automated-docker-test/test_deployment.yml up --abort-on-container-exit", as_root=True)
