import os
import urllib.request


def download_file(url, dest):
    """Download a file from a URL to a specified destination."""
    with urllib.request.urlopen(url) as response, open(dest, 'wb') as out_file:
        out_file.write(response.read())


def prepare_single_setup(setup_root, url_prover_key, url_main_c, url_main_c_dat, url_vk, url_circuit_config, url_generate_witness_js, url_main_wasm, url_witness_calculator_js):
    os.makedirs(setup_root, exist_ok=True)

    prover_key_path = os.path.join(setup_root, "prover_key.zkey")
    download_file(url_prover_key, prover_key_path)

    main_c_path = os.path.join(setup_root, "main_c")
    download_file(url_main_c, main_c_path)
    os.chmod(main_c_path, 0o744)

    main_c_dat_path = os.path.join(setup_root, "main_c.dat")
    download_file(url_main_c_dat, main_c_dat_path)

    vk_path = os.path.join(setup_root, "verification_key.json")
    download_file(url_vk, vk_path)

    circuit_config_path = os.path.join(setup_root, "circuit_config.yml")
    download_file(url_circuit_config, circuit_config_path)

    witness_calculator_js_path = os.path.join(setup_root, "generate_witness.js")
    download_file(url_generate_witness_js, witness_calculator_js_path)

    main_wasm_path = os.path.join(setup_root, "main.wasm")
    download_file(url_main_wasm, main_wasm_path)

    witness_calculator_js_path = os.path.join(setup_root, "witness_calculator.js")
    download_file(url_witness_calculator_js, witness_calculator_js_path)

def force_symlink_dir(target, link_path):
    if os.path.exists(link_path):
        assert os.path.islink(link_path)
        os.remove(link_path)
    os.symlink(target, link_path, target_is_directory=True)
