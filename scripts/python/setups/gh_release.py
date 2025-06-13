import urllib
import utils
from datetime import datetime

class ReleaseNotFound(Exception):
    def __init__(self, release_name):
        super().__init__("Release \"" + release_name + "\" not found.")
        self.release_name = release_name

class ReleaseMissingRequiredAsset(Exception):
    def __init__(self, release_name, required_asset):
        super().__init__("Release \"" + release_name + "\" is missing required asset \"" + required_asset + "\".")
        self.release_name = release_name
        self.required_asset = required_asset



class Releases:

    def __init__(self, repo='keyless-zk-proofs', auth_token=None):
        self.auth_token = auth_token
        self.data = utils.read_json_from_url(f"https://api.github.com/repos/aptos-labs/{repo}/releases", auth_token)
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

    def get_assets(self, release_name, asset_names):
        release = self.release_with_name(release_name)

        result = []

        for asset_name in asset_names:
            found = False
            for asset in release['assets']:
                if asset['name'] == asset_name:
                    result.append(asset)
                    found = True
                    break
            if not found:
                raise ReleaseMissingRequiredAsset(release_name, asset_name)

        return result


    def download_and_install_release(self, release_name, install_dir, asset_names):
        """Download a release named `release_name` and install into dir
           `release_dir`.
        """

        assets = self.get_assets(release_name, asset_names)
        for asset in assets:
            if self.auth_token:
                req = urllib.request.Request(asset['url'])
                req.add_header("Authorization", f"token {self.auth_token}")
                req.add_header("Accept", "Accept: application/octet-stream")
                utils.download_file(req, install_dir / asset['name'])
            else:
                utils.download_file(asset['browser_download_url'], install_dir / asset['name'])


