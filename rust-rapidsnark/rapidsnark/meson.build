# PROJECT DEF
#############

project(
'rapidsnark', 
'cpp',
default_options: [
  'buildtype=release',
  'debug=true',
  'cpp_std=c++17'
  ]
)

# If we are on x86-64, need nasm 
if build_machine.cpu_family() == 'x86_64'
  add_languages('nasm')
endif







# DEPENDENCIES
##############

cmake = import('cmake')

# gmp, assumed to be installed in system. See 
# https://mesonbuild.com/Dependencies.html#dependency-detection-method 
# for how meson searches for dependencies
gmp_dep = dependency('gmp')

# oneTBB subproject/dependency, included as a subproject; see ./subprojects/oneTBB.wrap
opt_var = cmake.subproject_options()

if build_machine.system() == 'darwin'
  opt_var.add_cmake_defines({
    'TBB_TEST': 'NO'
    })
else
  opt_var.add_cmake_defines({
    'TBB_TEST': 'NO',
    'CMAKE_SHARED_LINKER_FLAGS': '-fuse-ld=lld -Wl,-u'
    })
endif

tbb_dep = cmake.subproject('oneTBB', options: opt_var).dependency('tbb')


# nlohmann/json dependency, included as a subproject; see ./subprojects/json.wrap
json_dep = subproject('json').get_variable('nlohmann_json_dep')

# scope_guard dependency, included as a subproject; see ./subprojects/scope_guard.wrap
scope_guard_dep = cmake.subproject('scope_guard').dependency('scope_guard')

deps = [
  gmp_dep, 
  tbb_dep, 
  json_dep, 
  scope_guard_dep
  ]


# SOURCE FILES
##############


src_files_common = [ 
  'alt_bn128.cpp',
  'binfile_utils.cpp',
  'curve.cpp',
  'f2field.cpp',
  'fft.cpp',
  'fq.cpp',
  'fr.cpp',
  'fullprover.cpp',
  'groth16.cpp',
  'logger.cpp',
  'misc.cpp',
  'multiexp.cpp',
  'naf.cpp',
  'scalar.cpp',
  'splitparstr.cpp',
  #'splitparstr_test.cpp',
  #'test_prover.cpp',
  #'alt_bn128_test.cpp',
  ]

src_files_no_asm = [
  'fq_generic.cpp',
  'fq_raw_generic.cpp',
  'fr_generic.cpp',
  'fr_raw_generic.cpp'
  ]

src_files_asm = [
  'asm/fq.asm',
  'asm/fr.asm',
  ]

# PLATFORM-SPECIFIC LOGIC
#########################

# This flag ensures that the limb type in `gmp.h` and in rapidsnark match
# on darwin machines
if build_machine.system() == 'darwin' and build_machine.cpu_family() == 'aarch64'
  add_project_arguments('-D_LONG_LONG_LIMB', language : 'cpp')
endif

if build_machine.cpu_family() == 'x86_64'
  # fr.hpp and fq.hpp need these flags to choose the 
  # right fn signatures
  add_project_arguments('-DARCH_X86_64', language : 'cpp')
  add_project_arguments('-DUSE_ASM', language : 'cpp')

  src_files = src_files_common \
    + src_files_asm
else
  # fr.hpp and fq.hpp need these flags to choose the 
  # right fn signatures
  add_project_arguments('-DARCH_ARM', language : 'cpp')

  src_files = src_files_common \
    + src_files_no_asm
endif



# FINAL LIBRARY DEF
###################

src = []
foreach file : src_files
  src += ['src' / file ]
endforeach

rapidsnark_lib = static_library(
  'rapidsnark', 
  src, 
  dependencies: deps,
)

