import os
import utils


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

res_root = os.environ['RESOURCES_DIR']

utils.prepare_single_setup(
    setup_root=f'{res_root}/setup_2024_05',
    url_prover_key='https://github.com/aptos-labs/aptos-keyless-trusted-setup-contributions-may-2024/raw/main/contributions/main_39f9c44b4342ed5e6941fae36cf6c87c52b1e17f_final.zkey',
    url_main_c='https://github.com/aptos-labs/devnet-groth16-keys/raw/master/main_c_cpp/main_c',
    url_main_c_dat='https://github.com/aptos-labs/devnet-groth16-keys/raw/master/main_c_cpp/main_c.dat',
    url_vk='https://raw.githubusercontent.com/aptos-labs/aptos-keyless-trusted-setup-contributions-may-2024/a26b171945fb2d0b08b015ef80dbca14e4916821/verification_key_39f9c44b4342ed5e6941fae36cf6c87c52b1e17f.json',
    url_circuit_config='https://raw.githubusercontent.com/aptos-labs/aptos-keyless-trusted-setup-contributions-may-2024/a26b171945fb2d0b08b015ef80dbca14e4916821/circuit_config.yml',
    url_generate_witness_js='https://github.com/aptos-labs/devnet-groth16-keys/raw/master/main_js/generate_witness.js',
    url_main_wasm='https://github.com/aptos-labs/devnet-groth16-keys/raw/master/main_js/main.wasm',
    url_witness_calculator_js='https://github.com/aptos-labs/devnet-groth16-keys/raw/master/main_js/witness_calculator.js'
)

utils.prepare_single_setup(
    setup_root=f'{res_root}/setup_2025_01',
    url_prover_key='https://github.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/raw/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/contributions/main_final.zkey',
    url_main_c='https://github.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/raw/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/main_c_cpp_c60ae945e577295ac1a712391af1bcb337c584d2/main_c',
    url_main_c_dat='https://github.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/raw/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/main_c_cpp_c60ae945e577295ac1a712391af1bcb337c584d2/main_c.dat',
    url_vk='https://raw.githubusercontent.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/verification_key.json',
    url_circuit_config='https://raw.githubusercontent.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/circuit_config.yml',
    url_generate_witness_js='https://raw.githubusercontent.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/main_js_c60ae945e577295ac1a712391af1bcb337c584d2/generate_witness.js',
    url_main_wasm='https://github.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/raw/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/main_js_c60ae945e577295ac1a712391af1bcb337c584d2/main.wasm',
    url_witness_calculator_js='https://raw.githubusercontent.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/107bc39ea0bdf8c76e63d189157d8bb6b8ff04da/main_js_c60ae945e577295ac1a712391af1bcb337c584d2/witness_calculator.js'
)

utils.force_symlink_dir(f'{res_root}/setup_2024_05', f'{res_root}/default')
utils.force_symlink_dir(f'{res_root}/setup_2025_01', f'{res_root}/new')
