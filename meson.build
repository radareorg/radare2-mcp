project(
  'r2mcp',
  'c',
version : '1.2.0',
  default_options : ['warning_level=3', 'c_std=c11']
)

cc = meson.get_compiler('c')

# radare2 core dependency: use pkg-config when available. Do not fall back
# to CMake-based dependency discovery; instead, if pkg-config fails, try
# locating the library under user-provided prefixes (see -Dr2_prefix).
pkg = find_program('pkg-config', required: false)
if pkg.found()
  r_core_dep = dependency('r_core', method: 'pkg-config', required: false)
endif
if not r_core_dep.found()
  # Try locating radare2 from environment-provided prefixes. This helps CI on
  # Windows where pkg-config may not be installed and CMake lookup may fail.
  # Allow callers to pass a prefix via the meson option 'r2_prefix'. This is
  # easier to set from CI (meson setup -Dr2_prefix=...). See meson_options.txt.
  r2_prefixes = []
  if get_option('r2_prefix') != ''
    r2_prefixes += [get_option('r2_prefix')]
  endif

  foreach p : r2_prefixes
    # Common library/include locations under a provided prefix.
    libdirs = [
      join_paths(p, 'lib'),
      join_paths(p, 'lib64'),
      join_paths(p, 'radare2', 'lib'),
      join_paths(p, 'radare2', 'lib64'),
      join_paths(p, 'mingw64', 'lib'),
    ]
    incdirs = [
      join_paths(p, 'include'),
      join_paths(p, 'radare2', 'include'),
      join_paths(p, 'include', 'radare2'),
    ]
    # Try to find the core library in any of these lib dirs. Some radare2
    # releases and Windows installers place libraries in `bin` or use
    # slightly different names (version suffixes). Try several common
    # candidate names so Meson can locate the import library on MSVC or
    # the shared object/dll on mingw.
    extra_libdirs = libdirs + [ join_paths(p, 'bin') ]
    candidate_names = [ 'r_core', 'r_core-6', 'r_core6', 'r_core64', 'libr_core' ]
    foreach name : candidate_names
      rcore_lib = cc.find_library(name, dirs: extra_libdirs, required: false)
      if rcore_lib.found()
        rcore_inc = include_directories(incdirs + [ join_paths(p, 'include', 'libr') ])
        r_core_dep = declare_dependency(link_with: rcore_lib, include_directories: rcore_inc)
        break
      endif
    endforeach
  endforeach

  if not r_core_dep.found()
    error('Dependency lookup for r_core failed: install radare2 development files or provide pkg-config paths or set the meson option -Dr2_prefix=<prefix>')
  endif
endif

# Match Makefile warning flags when using gcc/clang
c_args = []
if cc.get_id() == 'gcc' or cc.get_id() == 'clang'
  c_args += ['-Wall', '-Wextra']
endif

srcs = [
  'src/main.c',
  'src/r2mcp.c',
  'src/readbuffer.c',
  'src/tools.c',
  'src/prompts.c',
]

executable(
  'r2mcp',
  srcs,
  dependencies: [r_core_dep],
  c_args: c_args,
  install: true,
)
