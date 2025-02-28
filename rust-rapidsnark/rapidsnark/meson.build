
project(
'rapidsnark', 
'cpp',
default_options: [
  'buildtype=release',
  'debug=true',
  'cpp_std=c++17'
  ]
)


cmake = import('cmake')


# for ffiasm
add_languages('nasm')

# b/c ffiasm uses these flags
# TODO: make this generic over linux and osx


# Required on macos because somehow the homebrew version of gmp has a library
# binary that supports 64-bit limbs, but gmp.h only allows this if you set this 
# flag
if build_machine.system() == 'darwin'
  add_project_arguments('-D_LONG_LONG_LIMB', language : 'cpp')
endif

gmp_dep = dependency('gmp')




# oneTBB subproject/dependency
opt_var = cmake.subproject_options()
opt_var.add_cmake_defines({'TBB_TEST': false})
tbb_dep = cmake.subproject('oneTBB').dependency('tbb')

deps = [gmp_dep, tbb_dep]


# I'm using `includes` for header-only libs
incdirs = include_directories('./includes')

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
  'main.cpp',
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

src = []
foreach file : src_files
  src += ['src' / file ]
endforeach

rapidsnark_lib = static_library(
  'rapidsnark', 
  src, 
  dependencies: deps,
  include_directories: incdirs
)

