from google.cloud import storage
from google.auth import default
from pathlib import Path
from google.cloud.storage import Client, transfer_manager
from google.cloud import storage
import google
from setup import testing_setup, Setup
import tempfile
from utils import eprint
from pathlib import Path
import tarfile
import os


def cache_bucket():
    credentials, project = default()
    client = storage.Client(credentials=credentials, project="aptos-data-staging")
    return client.get_bucket("aptos-keyless-testing")


def download_testing_setup_if_present():
    try:
        bucket = cache_bucket()
    except google.api_core.exceptions.Forbidden:
        eprint("You aren't authenticated to google cloud; can't check cache for setups.")
        return False


    blob_name = testing_setup.current_circuit_checksum() + ".tar.gz"
    blob = bucket.blob(blob_name)

    eprint("Checking cache...")
    if blob.exists():
        eprint("Setup for the current circuit found in the google cloud storage cache. Downloading...")
        with tempfile.TemporaryDirectory() as temp_dir:
            tarfile_path = Path(temp_dir) / blob_name
            blob.download_to_filename(tarfile_path)
            testing_setup.current_circuit_setup_path().mkdir(parents=True, exist_ok=True)
            with tarfile.open(tarfile_path, 'r:gz') as tar:
                tar.extractall(path=testing_setup.SETUPS_DIR)
        eprint("Finished downloading.")
        return True
    else:
        eprint("Setup for the current circuit was NOT found in the google cloud storage cache.")
        return False


def current_circuit_blob_exists():
    try:
        bucket = cache_bucket()
    except google.api_core.exceptions.Forbidden:
        eprint("You aren't authenticated to google cloud; can't check cache for setups.")
        return False


    blob_name = testing_setup.current_circuit_checksum() + ".tar.gz"
    blob = bucket.blob(blob_name)

    return blob.exists()


def upload_current_circuit_setup():
    try:
        bucket = cache_bucket()
    except google.api_core.exceptions.Forbidden:
        eprint("You aren't authenticated to google cloud; can't upload setup to cache.")
        return False

    with tempfile.TemporaryDirectory() as temp_dir:
        blob_name = testing_setup.current_circuit_checksum() + ".tar.gz"
        eprint("Creating tarfile with setup result...")
        tarfile_path = Path(temp_dir) / blob_name
        folder_path = testing_setup.current_circuit_setup_path()
        
        with tarfile.open(tarfile_path, "w:gz") as tar:
            tar.add(folder_path, arcname=os.path.basename(folder_path))
        
        eprint("Uploading to cache...")
        blob = bucket.blob(blob_name)
        blob.upload_from_filename(tarfile_path)
        eprint("Done uploading.")

