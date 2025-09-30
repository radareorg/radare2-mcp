project(
  'r2mcp',
  'c',
version : '1.2.0',
  default_options : ['warning_level=3', 'c_std=c11']
)

cc = meson.get_compiler('c')

# radare2 core dependency: use pkg-config when available
pkg = find_program('pkg-config', required: false)
if pkg.found()
  r_core_dep = dependency('r_core', method: 'pkg-config', required: false)
endif
if not r_core_dep.found()
  r_core_dep = dependency('r_core', required: false)
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
    # Try to find the core library in any of these lib dirs.
    rcore_lib = cc.find_library('r_core', dirs: libdirs, required: false)
    if rcore_lib.found()
      rcore_inc = include_directories(incdirs)
      r_core_dep = declare_dependency(link_with: rcore_lib, include_directories: rcore_inc)
      break
    endif
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
