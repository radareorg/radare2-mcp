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
  # On Windows prefer explicit discovery like other third_party projects do:
  # 1) ask an installed `radare2` binary for its lib/include/plugin dirs
  #    (via `radare2 -H R2_LIBDIR` / `R2_INCDIR`),
  # 2) fall back to -Dr2_prefix provided by CI, and
  # 3) try common locations such as C:\\radare2\\lib and <prefix>/bin.
  # This avoids Meson's CMake-based dependency fallback which doesn't work
  # reliably with radare2 release zips on Windows.
  is_windows_like = host_machine.system() == 'windows' or cc.get_id() == 'msvc' or cc.get_id() == 'clang-cl'

  found = false
  if is_windows_like
    radare2_prog = find_program('radare2', required: false)
    radare2_libdir = ''
    radare2_incdir = ''
    radare2_plugdir = ''
    if radare2_prog.found()
      rlib = run_command(radare2_prog, '-H', 'R2_LIBDIR', check: false)
      if rlib.returncode() == 0
        radare2_libdir = rlib.stdout().strip()
      endif
      rinc = run_command(radare2_prog, '-H', 'R2_INCDIR', check: false)
      if rinc.returncode() == 0
        radare2_incdir = rinc.stdout().strip()
      endif
      rplug = run_command(radare2_prog, '-H', 'R2_LIBR_PLUGINS', check: false)
      if rplug.returncode() == 0
        radare2_plugdir = rplug.stdout().strip()
      endif
    endif

    # Build candidate dirs from discovered locations or provided prefix
    candidate_dirs = []
    if radare2_libdir != ''
      candidate_dirs += [radare2_libdir]
    endif
    if get_option('r2_prefix') != ''
      p = get_option('r2_prefix')
      candidate_dirs += [ join_paths(p, 'lib'), join_paths(p, 'bin'), join_paths(p, 'radare2', 'lib'), join_paths(p, 'mingw64', 'lib') ]
    endif
    # Always try the conventional install location used by the CI helper
    candidate_dirs += [ 'C:\\radare2\\lib', 'C:/radare2/lib' ]

    # include dirs corresponding to candidate dirs (best-effort)
    incdirs = []
    if radare2_incdir != ''
      incdirs += [ radare2_incdir ]
    endif
    if get_option('r2_prefix') != ''
      p = get_option('r2_prefix')
      incdirs += [ join_paths(p, 'include'), join_paths(p, 'include', 'radare2'), join_paths(p, 'include', 'libr') ]
    endif

    candidate_names = [ 'r_core', 'r_core-6', 'r_core6', 'r_core64', 'libr_core' ]
    foreach name : candidate_names
      foreach d : candidate_dirs
        rcore_lib = cc.find_library(name, dirs: [d], required: false)
        if rcore_lib.found()
          rcore_inc = include_directories(incdirs + [ join_paths(d, '..', 'include', 'libr'), join_paths(d, '..', 'include') ])
          r_core_dep = declare_dependency(link_with: rcore_lib, include_directories: rcore_inc)
          found = true
          break
        endif
      endforeach
      if found
        break
      endif
    endforeach

    if not found
      error('Windows dependency lookup for r_core failed: ensure radare2 is installed and pass -Dr2_prefix=<prefix> or make the `radare2` executable available on PATH')
    endif
  else
    # Non-Windows: try locating radare2 from environment-provided prefixes. This
    # helps CI on Unix where pkg-config may not be installed.
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
      extra_libdirs = libdirs + [ join_paths(p, 'bin') ]
      candidate_names = [ 'r_core', 'r_core-6', 'r_core6', 'r_core64', 'libr_core' ]
      foreach name : candidate_names
        rcore_lib = cc.find_library(name, dirs: extra_libdirs, required: false)
        if rcore_lib.found()
          rcore_inc = include_directories(incdirs + [ join_paths(p, 'include', 'libr') ])
          r_core_dep = declare_dependency(link_with: rcore_lib, include_directories: rcore_inc)
          found = true
          break
        endif
      endforeach
      if found
        break
      endif
    endforeach

    if not found
      error('Dependency lookup for r_core failed: install radare2 development files or provide pkg-config paths or set the meson option -Dr2_prefix=<prefix>')
    endif
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
