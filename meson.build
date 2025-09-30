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
r_core_dep = dependency('r_core', method: 'pkg-config', required: false)

# If pkg-config didn't yield an r_core dependency, fall back to manual
# discovery logic below (search common prefixes / extracted zips).
if not r_core_dep.found()
  # On Windows prefer explicit discovery like other third_party projects do:
  # 1) ask an installed `radare2` binary for its lib/include/plugin dirs
  #    (via `radare2 -H R2_LIBDIR` / `R2_INCDIR`),
  # 2) fall back to -Dr2_prefix provided by CI, and
  # 3) try common locations such as C:\\radare2\\lib and <prefix>/bin.
  # This avoids Meson's CMake-based dependency fallback which doesn't work
  # reliably with radare2 release zips on Windows.
  is_windows_like = host_machine.system() == 'windows' or cc.get_id() == 'msvc' or cc.get_id() == 'clang-cl'

  # Simpler, robust Windows behavior mirroring third_party projects:
  # Try to find r_core by checking a small list of likely library dirs.
  if is_windows_like
    r2libdirs = []
    # prefer explicit prefix if given
    if get_option('r2_prefix') != ''
      p = get_option('r2_prefix')
      r2libdirs += [ join_paths(p, 'lib'), join_paths(p, 'radare2', 'lib') ]
    endif
    # repository-local radare2 (used by some subprojects) and conventional path
    r2libdirs += [ meson.current_source_dir() + '/radare2/lib', 'C:/radare2/lib']

    # try to find r_core in the candidate dirs (MSVC import libs or mingw import libs)
    rcore_lib = cc.find_library('r_core', dirs: r2libdirs, required: false)
    if not rcore_lib.found()
      rcore_lib = cc.find_library('libr_core', dirs: r2libdirs, required: false)
    endif

    if rcore_lib.found()
      # basic include candidates
      incdirs = []
      if get_option('r2_prefix') != ''
        p = get_option('r2_prefix')
        incdirs += [ join_paths(p, 'include', 'libr'), join_paths(p, 'include') ]
      endif
      rcore_inc = include_directories(incdirs)
      r_core_dep = declare_dependency(link_with: rcore_lib, include_directories: rcore_inc)
    else
      error('Windows dependency lookup for r_core failed: ensure radare2 is installed and pass -Dr2_prefix=<prefix> (e.g. C:/radare2)')
    endif
  else
    # Non-Windows: try locating radare2 from environment-provided prefixes. This
    # helps CI on Unix where pkg-config may not be installed.
    r2_prefixes = []
    if get_option('r2_prefix') != ''
      r2_prefixes += [get_option('r2_prefix')]
    endif

    found = false
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
elif cc.get_id() == 'msvc' or cc.get_id() == 'clang-cl'
  # MSVC-specific flags
  c_args += ['/W3']  # Warning level 3
  c_args += ['/wd4996']  # Disable deprecated function warnings
  c_args += ['/wd4101']  # Disable unreferenced local variable warnings
endif

srcs = [
  'src/main.c',
  'src/r2mcp.c',
  'src/readbuffer.c',
  'src/tools.c',
  'src/prompts.c',
]

# Windows-specific configuration
if host_machine.system() == 'windows'
  # Copy Windows config header
  configure_file(
    input: 'config.h.w64',
    output: 'config.h',
    copy: true
  )
  
  # Windows-specific link arguments
  link_args = []
  if cc.get_id() == 'msvc' or cc.get_id() == 'clang-cl'
    link_args += ['/SUBSYSTEM:CONSOLE']
    link_args += ['/DEFAULTLIB:setupapi.lib']
  endif
else
  # Non-Windows: use configure script to generate config.h
  configure_file(
    input: 'src/config.h.acr',
    output: 'config.h',
    configuration: configuration_data()
  )
  link_args = []
endif

executable(
  'r2mcp',
  srcs,
  dependencies: [r_core_dep],
  c_args: c_args,
  link_args: link_args,
  install: true,
)
