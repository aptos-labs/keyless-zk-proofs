import utils
from datetime import datetime

GH_RELEASES_URL = "https://api.github.com/repos/aptos-labs/keyless-zk-proofs/releases"

class ReleaseNotFound(Exception):
    def __init(self, release_name):
        super().__init__("Release \"" + release_name + "\" not found.")
        self.release_name = release_name

class ReleaseMissingRequiredAsset(Exception):
    def __init(self, release_name, required_asset):
        super().__init__("Release \"" + release_name + "\" is missing required asset \"" + required_asset + "\".")
        self.release_name = release_name
        self.required_asset = required_asset



class Releases:

    def __init__(self):
        self.data = utils.read_json_from_url(GH_RELEASES_URL)
        # Convert the 'created_at' field to a datetime so that we can
        # sort based on it
        for release in self.data:
            release['created_at'] = \
              datetime.fromisoformat(release['created_at'])
        # Sort based on release creation time
        self.data.sort(key=lambda release: release['created_at'])

    def release_names(self):
        return [ release['tag_name'] for release in self.data ]

    def release_with_name(self, release_name):
        for release in self.data:
            if release['tag_name'] == release_name:
                return release

        raise ReleaseNotFound(release_name)

    def check_release_contains_assets(self, release_name, required_assets):
        """Check if release `release_name` contains all assets in `required_assets`,
        matching by filename. Throw an exception if an asset is not found."""

        release = self.release_with_name(release_name)

        for required_asset in required_assets:
            if required_asset not in [ asset['name'] for asset in release.assets ]:
                throw ReleaseMissingRequiredAsset(release_name, required_asset)


    def download_and_install_release(self, release_name, install_dir, assets):
        """Download a release named `release_name` and install into dir
           `release_dir`.
        """

        self.check_release_contains_assets(release_name, assets)
        release = self.release_with_name(release_name)


        


