# Changelog

Currently this contains the changes from the last few of Rex's PRs.

## PR #44: Automate testing docker image

This PR adds the `automated-docker-test` folder, which contains resources
that allow for running an automated test of a prover service docker image.
See the [README](./automated-docker-test/README.md) for more details.

## PR #43: Minor script/CI improvements 

Does the following:

* Make task.sh not print 'file not found' and 'package not found' messages
* Print out ptau file path when downloading/verifying checksum so that it's
  easy to find when there are errors
* Change macos CI tests to run on a larger VM, so that it hopefully won't
  run out of memory when doing a local testing setup
* Fix autocompletion

## PR #43: Fix prover service 

This PR does the following:

* Changes `prover_service/circuit_config.yml` to work with the audless
  version of the circuit
* Since prover service tests will now pass for the current version of the
  circuit (i.e., the one in `circuit/templates`), sets the GH workflow to
  run tests with a testing setup corresponding to whatever circuit is in
  the repo
* Removes an extraneous `main.cpp` file:
  `rust-rapidsnark/rapidsnark/src/main.cpp`. We don't use it, and it was
  causing issues with compilation on Zhoujun's machine
* Misc bugfixes in `scripts`

## PR #39: New setup procurement

This PR changes the `./task.sh` actions that procure the setups (prover key, verification key, circuit config, witness gen binaries). It also cleans up the `task.sh` actions more generally.

Previously, there was a single action that downloaded these resources from old ceremony repo URLs that were hardcoded in the scripts. Now, there are two options for procuring a setup:

### Locally-generated testing setup

Running `./scripts/task.sh setup procure-testing-setup` will do the following:

- Computes a hash of the circuit currently in the repo.
  - Note that currently this hash is computed from the circuit *source code*, not the R1CS file. This is because compiling the circuit itself takes a minute, and I don't want to wait one minute just to obtain an identifier for the circuit
- Checks a google cloud storage GCS bucket (refer to this as the "cache" from now on) whether there is already a setup for this circuit.
- If present in the cache, downloads it.
  - If the downloaded setup was built on an arm machine, it won't contain the C witness gen binaries. If the local machine is an x86-64 machine and the downloaded setup does not contain them, the script will build these C binaries and re-upload the setup.
- If not present, compiles the circuit and witness gen binaries and runs a local (1-person) setup.
- Installs the setup in the correct location, so that running `cargo test -p prover-service` will use this setup.
- Uploads the setup to the cloud.

**Note:** Right now, the GCS bucket requires being authenticated to GC with an Aptos account to use, since Stelian has not yet provided us with a bucket that allows for unauthenticated read access. So if you try to run this action without running `gcloud auth login --update-adc`, the script builds the setup locally and does not upload to the cache.

### Setup ceremonies from releases

Running `./scripts/task.sh setup download-ceremonies-for-releases <default-release> <new-release> --witness-gen-type {none,c,wasm,both}` will do the following:

- Use `https://api.github.com/repos/aptos-labs/keyless-zk-proofs/releases` to get a list of releases for `keyless-zk-proofs`
- Verify that `<default-release>` and `<new-release>` exist, and they have the required assets. Depending on the value of `--witness-gen-type`, this could include c or wasm witness gen binaries, or both
- Download these assets and install them in the correct place so that running `cargo test -p prover-service` will use this setup.


### Misc. Cleanup

- the `task.sh` now uses the `typer` library, which automatically builds usage strings for each command using the corresponding python function's docstring.
- The repo now has a new action that runs cargo tests **on macos**, in addition to the one that runs cargo tests on linux. This is so that we stop missing platform-specific edge cases; if a PR gets merged to main, it should be guaranteed to build both on macos/ARM and linux/x86-64.


### Todo

- [x] Make `task.sh setup-dev-environment` procure a local testing setup by default
- [x] add a reminder to `gcloud auth login --update-adc` if not logged in
- [x] Make sure all actions have docstrings
- [x] Double-check `cargo test -p prover-service`
- [x] docker image: hardcode circuit release tags for now


## PR #37: Rewrite setup scripts

This PR stacks on the [repo reorganization PR](https://github.com/aptos-labs/keyless-zk-proofs/pull/32). The goal of this PR is to rewrite the scripts in the repo and to reorganize them into one place, and to update the Dockerfile and all READMEs accordingly.

### Issues addressed

* There were previously several `dev_setup` and `install_deps` scripts in various subdirectories. Each script installed dependencies and/or setup the environment for one of the components in this repo. The boundaries between the actions defined by these scripts were not well-defined.
* Because of this poor separation of actions:
  *  There were three different places that defined the dependencies needed for the prover service: in its `dev_setup` script, in the Dockerfile, and in the github workflow script.
  * There was a single script that the Dockerfile invoked to download the trusted setup and witness-generation binaries, and this script downloaded both the C and wasm versions of the witness generation binaries. This meant that unneeded files were included in the final prover service docker image.

### Changes

* There is now a `scripts` directory in the repo root which defines all actions needed for this repo.
* There is now a single entry-point for running actions: `scripts/task.sh`. This shell script is a "wrapper" script, which:
  * checks if `python3` and `curl` are present on the system, and installs them if not
  * invokes `scripts/python/main.py`, which defines and handles all the actions for this repo.
* All actions are now defined in python. This allows for much better code reuse across actions than in bash. For instance, there is now a [specific python module](https://github.com/aptos-labs/keyless-zk-proofs/blob/rex/rewrite_setup_scripts/scripts/python/utils/manage_deps.py) which provides convenient functions for cross-platform installation of a given dependency. 
*  Actions are now well-defined enough to avoid the issues above:
  * There is a [single action for installing the prover-service dependencies](https://github.com/aptos-labs/keyless-zk-proofs/blob/5242c41fe299229392f7d99ae2b022d1a7a1e860/scripts/python/prover_service.py#L4). This action is invoked:
    * as a sub-action when [setting up the development environment for the repo](https://github.com/aptos-labs/keyless-zk-proofs/blob/5242c41fe299229392f7d99ae2b022d1a7a1e860/scripts/python/main.py#L71)
    * [in the Dockerfile](https://github.com/aptos-labs/keyless-zk-proofs/blob/5242c41fe299229392f7d99ae2b022d1a7a1e860/prover-service/Dockerfile#L9) when building the prover service
    * [in the github workflow](https://github.com/aptos-labs/keyless-zk-proofs/blob/5242c41fe299229392f7d99ae2b022d1a7a1e860/.github/workflows/run-tests.yaml#L23) when running tests.
  * [Downloading the trusted setup](https://github.com/aptos-labs/keyless-zk-proofs/blob/5242c41fe299229392f7d99ae2b022d1a7a1e860/scripts/python/trusted_setup/__init__.py#L46), [downloading the C witness-gen binaries](https://github.com/aptos-labs/keyless-zk-proofs/blob/5242c41fe299229392f7d99ae2b022d1a7a1e860/scripts/python/trusted_setup/__init__.py#L59), and [downloading the wasm witness generation binaries](https://github.com/aptos-labs/keyless-zk-proofs/blob/5242c41fe299229392f7d99ae2b022d1a7a1e860/scripts/python/trusted_setup/__init__.py#L72) are now three separately-invokable actions.
    * The Dockerfile [invokes the first two actions](https://github.com/aptos-labs/keyless-zk-proofs/blob/5242c41fe299229392f7d99ae2b022d1a7a1e860/prover-service/Dockerfile#L20), and skips the third one, since it does not need the wasm binaries.
    * The action for setting up the development environment [invokes all three actions above](https://github.com/aptos-labs/keyless-zk-proofs/blob/5242c41fe299229392f7d99ae2b022d1a7a1e860/scripts/python/main.py#L76), so that testing is possible both on arm and on x86-64 machines. (**Possible alternative:** test for architecture and download wasm only if not x86-64.)
* The Dockerfile now runs the trusted-setup download actions inside the build image, not inside the final image. This means that the final image does not need to install python3 or curl, and has only what is necessary to invoke the prover service binary. 



## PR #32: Reorganization: removal of submodules, rewrite of Rapidsnark build system, misc. cleanup

**Note:** You do not need to set `LD_LIBRARY_PATH` to run the prover service test anymore. Running `dev_setup.sh` adds this to your `~/.profile` automatically.

The goal of this PR is to improve the portability and maintainability of the prover service. The prover service relies on `rapidsnark`, whose code organization and build system have caused portability issues for us in the past. 

### Issues addressed

- `rapidsnark` requires `gmp`; on linux, the system's `gmp` was used, but on MacOS, the `gmp` installed by homebrew caused compile errors, so our build script compiled `gmp` from scratch. 
- `rapidsnark` includes x86 assembly code for finite field operations, with a c++ fallback for arm systems; the build system was overly complicated and has caused problems related to choosing the correct implementation.
- `rapidsnark` included several dependencies which aren't used.
- The repo made heavy use of submodules. `rapidsnark` is wrapped in a rust crate `rust-rapidsnark`, which is a submodule of this repo inside the `prover-service` directory. `rapidsnark` itself is then a submodule of `rust-rapidsnark`, and `rapidsnark`'s dependencies are submodules of `rapidsnark`.

### Changes to `rapidsnark` 

- Removed the old CMake build system and replaced it with a much simpler meson build system, with [a single, easily-understandable file](https://github.com/aptos-labs/keyless-zk-proofs/blob/rex/reorganization/rust-rapidsnark/rapidsnark/meson.build) that defines the build.
  - The dependency `tbb` which we use for parallelism still uses CMake. Meson has a "subprojects" system for building dependencies, and allows for building subprojects with CMake, so we use this to build `tbb`. (We would like to avoid this entirely by installing `tbb` using the system's package manager, but `tbb` doesn't seem to be packaged in homebrew or apt right now.)
- Determined the `gmp`-related compile error on MacOS had to do with `gmp`'s limb type. See below for details. Fixing this issue means that we can always use the system's `gmp` and no longer have to include logic to build `gmp` on MacOS machines.
- Removed `circom_runtime`, `cpp-httplib`, and `pistache` dependencies, as they weren't used.
- Removed `json` header-only dependency git submodule; Meson now downloads this dependency during build 
- Removed scope_guard header-only dependency from the src directory; Meson now downloads this dependency during build
- Before, the ffiasm source files were spread all over the repo: some of the c++ files were in the `ffiasm` module in the `depends` directory, some others c++ and asm files were in `build`. Now all source files (both `rapidsnark` and `ffiasm` are in is in `src`, with asm files in `src/asm`.
- Further misc. cleanup of the `rapidsnark` source code. The importing logic was highly nonstandard (e.g., with header files that import the corresponding `.cpp` files, instead of the other way around). Changed the imports to follow more standard C++ conventions.
- ~~Changed `tbb` to be directly part of `rapidsnark` and not a submodule.~~ Changed `tbb` to be a "wrapfile subproject" in Meson. This means that Meson downloads and builds a `tbb` release from github during the rapidsnark build. Together with removing the other dependencies above, this means `rapidsnark` no longer contains any submodules.
- Modified `dev_setup.sh` to set `LD_LIBRARY_PATH` in order to allow running the prover service tests.


#### `gmp`'s limb type

The limb type's instantiation is chosen by `gmp`'s build script at compile time based on the OS and architecture, but `rapidsnark` assumes the type is `uint64_t`. On linux/X86-64, the types do match (both are `long`), but on the MacOS/ARM64 version of `gmp` installed by homebrew, the type in `gmp` (`long`) is different than `uint64_t` (which is `long long`). However, this difference is only at the source level; when compiled to ARM64, the code uses 64-bit registers on both ends.  

This means that the problem is solely at compile time, and is solely due to `gmp.h`'s definition of its limb type. Looking at the code of `gmp.h`, it turns out that it is defined as follows:

```
#ifdef __GMP_SHORT_LIMB
typedef unsigned int		mp_limb_t;
typedef int			mp_limb_signed_t;
#else
#ifdef _LONG_LONG_LIMB
typedef unsigned long long int	mp_limb_t;
typedef long long int		mp_limb_signed_t;
#else
typedef unsigned long int	mp_limb_t;
typedef long int		mp_limb_signed_t;
#endif
#endif
```

This means that if we define `_LONG_LONG_LIMB` when compiling rapidsnark, the types in `gmp.h` and `rapidsnark`'s source will match. It is important to reiterate that _this only works because the two types get compiled to use the same 64-bit registers._ I.e., this is only a mismatch in the C++ source code, not in the compiled binaries. 

See [here](https://github.com/aptos-labs/keyless-zk-proofs/blob/bf2e778e444c7da23f4f8b86f92b82ca937dfb24/rust-rapidsnark/rapidsnark/meson.build#L86) for the part of the build script that sets this flag when building on MacOS. 

### Changes to the repo structure

- Before, the prover service's crate name was `prover-service`, but the subdirectory was named `prover`. Renamed this directory to `prover-service` so that the two names are consistent.
- `rust-rapidsnark` is now in the repo root instead of in `prover-service`, and is a part of the workspace. `Cargo.toml`s have been updated to reflect this.
- `rust-rapidsnark` is now directly part of this repo instead of being a submodule.
- `rapidsnark` is now directly part of repo, instead of being a recursive submodule.
- Updated Dockerfile and github workflows to work with new repo organization.

### Remaining Issues/Alternatives

Including `rapidsnark` as part of the repo means that the lines of code in the repo goes up by a nontrivial amount. Currently, `rapidsnark` is around 28k lines of C++ code and 20k lines of assembly. In contrast, the total number of lines of rust code in this repo is around 8k. The argument could be made for keeping `rapidsnark` as a separate repo and importing it as a submodule, to keep the LOC down in this repo.

I believe that the current approach of one repo for everything is the better alternative, for the following reasons:
* Currently, the way that we test `rapidsnark` is by running the prover tests. It makes sense to keep those tests in the same repo as the `rapidsnark` code.
* I am hoping in the future to rewrite parts of `rapidsnark`. Keeping everything in the same repo will make that rewrite easier. The rewrite should also reduce the number of lines of code significantly:
  * There is a lot of needless assembly in the current version. Currently, rapidsnark implements their entire finite field module in assembly, whereas preliminary benchmarking seems to show the only function that really needs handwritten assembly is finite field multiplication. Every other function can be implemented in C++ with similar performance.
  * I believe there is other duplicated code in the rapidsnark codebase, although I need to explore further.



