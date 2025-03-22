import tarfile
import hashlib
import io
import os
import urllib.request
import sys
import shutil
from subprocess import Popen, PIPE
import subprocess
from os import environ
from pathlib import Path
import tempfile
import contextlib
import json

envvars_were_added = False

def repo_root():
    """Return the repo root. Assumes this script is two subdirectories in."""
    return Path(os.path.realpath(__file__)).parents[3]

def resources_dir_root():
    if 'RESOURCES_DIR' in os.environ:
        return Path(os.environ['RESOURCES_DIR'])
    else:
        return Path(os.path.expanduser("~/.local/share/aptos-keyless"))


def download_and_run_shell_script(url):
    """Download and run shell command at the given URL and exit if it fails."""
    run_shell_command("curl \"" + url + "\" | bash")

def download_and_run_shell_script_with_opts(url, opts):
    """Download and run shell command at the given URL and exit if it fails."""
    run_shell_command("curl \"" + url + "\" | bash -s -- " + opts)

def run_shell_command(command, as_root=False):
    """Run a command in a shell and exit if it fails."""
    try:
        if as_root:
            if shutil.which("sudo"):
                command = "sudo " + command
            else:
                eprint("sudo not found. Assuming you don't need privilege escalation.")

        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        eprint(f"Error: Command '{' '.join(command)}' failed with error {e}.")
        sys.exit(1)
    except Exception as e:
        eprint(f"Error: Command '{' '.join(command)}' failed with error {e}.")
        sys.exit(1)


def cargo_install_from_git(repo, ref=None):
    with tempfile.TemporaryDirectory() as temp_dir:
        with contextlib.chdir(temp_dir):
            run_shell_command("git clone '" + repo + "' repo_dir")
            with contextlib.chdir("repo_dir"):
                if ref:
                    run_shell_command("git switch -d " + ref)
                run_shell_command("cargo build --release")
                run_shell_command("cargo install --path circom")
            

def add_envvar_to_profile(name, value):
    """
    Adds an 'export name=value' line to the user's .bashrc or .zshrc file, if 
    this line doesn't already exist. Chose these files instead of .profile 
    and .zprofile because the latter are only loaded on login shells 
    (i.e., not when using ssh)
    """
    global envvars_were_added

    if "SHELL" in os.environ:
        if "bash" in os.environ["SHELL"]:
            profile_file_path = os.path.expanduser("~/.bashrc")
        elif "zsh" in os.environ["SHELL"]:
            profile_file_path = os.path.expanduser("~/.zshrc")
        else:
            eprint("Cannot detect the user's shell to add envvars. Only supports bash and zsh right now. Exiting.")
            exit(2)
    else:
        eprint("Not in a shell. Not adding envvar to path.")
        return

    new_profile_line="export " + name + "=\"" + value + "\""

    with open(profile_file_path, "r") as profile_file:
        if new_profile_line in profile_file.read():
            eprint("Line for envvar " + name + " already in " + profile_file_path + " so we won't add it again")
            return



    with open(profile_file_path, "a") as profile_file:
        profile_file.write(new_profile_line + "\n")


    envvars_were_added = True


def remind_to_restart_shell_if_needed():
    global envvars_were_added 

    if envvars_were_added:
        eprint("Env-vars were added to your profile. Please restart your shell.") 


def download_file(url, dest):
    """Download a file from a URL to a specified destination."""
    with urllib.request.urlopen(url) as response, open(dest, 'wb') as out_file:
        out_file.write(response.read())


def read_json_from_url(url, auth_token=None):
    """Read JSON from a URL and return a corresponding python dict"""
    if auth_token:
        headers = { 'Authorization': f'Bearer {auth_token}' }
    else:
        headers = {}
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read())


def delete_contents_of_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)
    for file in os.listdir(path):
        path = path / file
        if path.is_dir():
            shutil.rmtree(path)
        elif path.is_symlink():
            os.unlink(path)
        else:
            os.remove(path)

def file_checksum(path):
    """Return a SHA256 checksum of a file. Compatible with `sha256sum`."""
    with open(path, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()

def directory_checksum(directory):
    """Return a SHA256 checksum of (a tar file of) a directory and all its contents."""
    # Create a BytesIO buffer to hold the tar archive in memory
    tar_buffer = io.BytesIO()
    
    # Create the tar archive in the buffer
    with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
        tar.add(directory, arcname=os.path.basename(directory))
    
    # Get the tar archive data from the buffer
    tar_data = tar_buffer.getvalue()
    
    # Compute the SHA-256 checksum
    sha256_hash = hashlib.sha256(tar_data).hexdigest()
    
    return sha256_hash

def force_symlink_dir(target, link_path):
    if os.path.exists(link_path):
        assert os.path.islink(link_path)
        os.remove(link_path)
    os.symlink(target, link_path, target_is_directory=True)


def eprint(s):
    print(s, file=sys.stderr)




