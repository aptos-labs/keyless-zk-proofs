import os
import utils


def download_setup(setup):
    os.makedirs(setup.setup_root, exist_ok=True)

    prover_key_path = os.path.join(setup.setup_root, "prover_key.zkey")
    utils.download_file(setup.url_prover_key, prover_key_path)

    vk_path = os.path.join(setup.setup_root, "verification_key.json")
    utils.download_file(setup.url_vk, vk_path)

    circuit_config_path = os.path.join(setup.setup_root, "circuit_config.yml")
    utils.download_file(setup.url_circuit_config, circuit_config_path)



def download_witness_gen_binaries_c(setup):
    os.makedirs(setup.setup_root, exist_ok=True)


    main_c_path = os.path.join(setup.setup_root, "main_c")
    utils.download_file(setup.url_main_c, main_c_path)
    os.chmod(main_c_path, 0o744)

    main_c_dat_path = os.path.join(setup.setup_root, "main_c.dat")
    utils.download_file(setup.url_main_c_dat, main_c_dat_path)

    witness_calculator_js_path = os.path.join(setup.setup_root, "generate_witness.js")
    utils.download_file(setup.url_generate_witness_js, witness_calculator_js_path)

    main_wasm_path = os.path.join(setup.setup_root, "main.wasm")
    utils.download_file(setup.url_main_wasm, main_wasm_path)

    witness_calculator_js_path = os.path.join(setup.setup_root, "witness_calculator.js")
    utils.download_file(setup.url_witness_calculator_js, witness_calculator_js_path)

def download_witness_gen_binaries_wasm(setup):
    os.makedirs(setup.setup_root, exist_ok=True)


    main_c_path = os.path.join(setup.setup_root, "main_c")
    utils.download_file(setup.url_main_c, main_c_path)
    os.chmod(main_c_path, 0o744)

    main_c_dat_path = os.path.join(setup.setup_root, "main_c.dat")
    utils.download_file(setup.url_main_c_dat, main_c_dat_path)

    witness_calculator_js_path = os.path.join(setup.setup_root, "generate_witness.js")
    utils.download_file(setup.url_generate_witness_js, witness_calculator_js_path)

    main_wasm_path = os.path.join(setup.setup_root, "main.wasm")
    utils.download_file(setup.url_main_wasm, main_wasm_path)

    witness_calculator_js_path = os.path.join(setup.setup_root, "witness_calculator.js")
    utils.download_file(setup.url_witness_calculator_js, witness_calculator_js_path)


def force_symlink_dir(target, link_path):
    if os.path.exists(link_path):
        assert os.path.islink(link_path)
        os.remove(link_path)
    os.symlink(target, link_path, target_is_directory=True)

