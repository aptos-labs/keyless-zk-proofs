import shutil
import utils
from utils import eprint
import os
import stat
import pathlib


def compute_sample_proof():
    eprint("compute_sample_proof")
    eprint("Not yet implemented")
    exit(2)


def install_circom_precommit_hook():
    eprint("Installing precommit hook...")

    hook_dest_path = utils.repo_root() + "/.git/hooks/pre-commit"

    pathlib.Path(hook_dest_path).unlink(True)
    shutil.copyfile(utils.repo_root() + "/git-hooks/compile-circom-if-needed-pre-commit", hook_dest_path)
    os.chmod(hook_dest_path, stat.S_IXOTH )
    
    eprint("Done.")


