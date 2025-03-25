from google.cloud import storage
from google.auth import default
from pathlib import Path
from google.cloud.storage import Client, transfer_manager
from google.cloud import storage
import google
import tempfile
from utils import eprint
from pathlib import Path
import tarfile
import os

def cache_bucket_for_upload():
    credentials, project = default()
    client = storage.Client(credentials=credentials, project="aptos-keyless-prod")
    return client.get_bucket("aptos-circuit-testing-setups")

def cache_bucket():
    anonymous_client = storage.Client.create_anonymous_client()
    return anonymous_client.bucket("aptos-circuit-testing-setups")


def download_blob_if_present(name, dest):
    try:
        bucket = cache_bucket()
    except google.api_core.exceptions.Forbidden:
        eprint("Forbidden: you aren't authenticated to google cloud; can't download setup.")
        eprint("Please download the google cloud-cli (on macos: `brew install google-cloud-sdk`)")
        eprint("and then run `gcloud auth login --update-adc` to authenticate yourself.")
        return False
    except google.auth.exceptions.RefreshError:
        eprint("Your google cloud credentials have expired; can't download setup.")
        eprint("Please run `gcloud auth login --update-adc` to reauthenticate yourself.")
        return False
    except google.auth.exceptions.DefaultCredentialsError:
        eprint("You aren't authenticated to google cloud; can't download setup.")
        eprint("Please download the google cloud-cli (on macos: `brew install google-cloud-sdk`)")
        eprint("and then run `gcloud auth login --update-adc` to authenticate yourself.")
        return False


    blob_name = name + ".tar.gz"
    blob = bucket.blob(blob_name)

    eprint("Checking cache...")
    if blob.exists():
        eprint("Setup for the current circuit found in the google cloud storage cache. Downloading...")
        with tempfile.TemporaryDirectory() as temp_dir:
            tarfile_path = Path(temp_dir) / blob_name
            blob.download_to_filename(tarfile_path)
            with tarfile.open(tarfile_path, 'r:gz') as tar:
                tar.extractall(path=dest)
        eprint("Finished downloading.")
        return True
    else:
        eprint("Setup for the current circuit was NOT found in the google cloud storage cache.")
        return False


def blob_exists(name):
    try:
        bucket = cache_bucket()
    except google.api_core.exceptions.Forbidden:
        eprint("You aren't authenticated to google cloud; can't check cache for setups.")
        eprint("Please download the google cloud-cli (on macos: `brew install google-cloud-sdk`)")
        eprint("and then run `gcloud auth login --update-adc` to authenticate yourself.")
        # Hacky to return true here
        return True
    except google.auth.exceptions.RefreshError:
        eprint("Your google cloud credentials have expired. Please run `gcloud auth login --update-adc` to re-authenticate.")
        # Hacky to return true here
        return True
    except google.auth.exceptions.DefaultCredentialsError:
        eprint("You aren't authenticated to google cloud; can't upload setup to cache.")
        eprint("Please download the google cloud-cli (on macos: `brew install google-cloud-sdk`)")
        eprint("and then run `gcloud auth login --update-adc` to authenticate yourself.")
        # Hacky to return true here
        return True

    blob_name = name + ".tar.gz"
    blob = bucket.blob(blob_name)
    return blob.exists()


def upload_to_blob(name, folder):
    try:
        bucket = cache_bucket_for_upload()
    except google.api_core.exceptions.Forbidden:
        eprint("You aren't authenticated to google cloud; can't upload setup to cache.")
        eprint("Please download the google cloud-cli (on macos: `brew install google-cloud-sdk`)")
        eprint("and then run `gcloud auth login --update-adc` to authenticate yourself.")
        return False
    except google.auth.exceptions.RefreshError:
        eprint("Your google cloud credentials have expired; can't upload setup to cache.")
        eprint("Please run `gcloud auth login --update-adc` to reauthenticate yourself.")
        return False
    except google.auth.exceptions.DefaultCredentialsError:
        eprint("You aren't authenticated to google cloud; can't upload setup to cache.")
        eprint("Please download the google cloud-cli (on macos: `brew install google-cloud-sdk`)")
        eprint("and then run `gcloud auth login --update-adc` to authenticate yourself.")
        return False

    with tempfile.TemporaryDirectory() as temp_dir:
        blob_name = name + ".tar.gz"
        eprint("Creating tarfile with setup result...")
        tarfile_path = Path(temp_dir) / blob_name
        
        with tarfile.open(tarfile_path, "w:gz") as tar:
            tar.add(folder, arcname=os.path.basename(folder))
        
        eprint("Uploading to cache...")
        blob = bucket.blob(blob_name)
        blob.upload_from_filename(tarfile_path)
        eprint("Done uploading.")

