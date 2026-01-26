project(
  'r2mcp',
  'c',
version : '1.5.4',
  default_options : ['warning_level=2', 'c_std=c11']
)

cc = meson.get_compiler('c')

r_core_dep = dependency('r_core', method: 'pkg-config', required: false)

r2_libdirs = []
r2_incdirs = []

if not r_core_dep.found()
  is_windows_like = host_machine.system() == 'windows' or cc.get_id() == 'msvc' or cc.get_id() == 'clang-cl'

  if is_windows_like
    r2libdirs = []
    if get_option('r2_prefix') != ''
      p = get_option('r2_prefix')
      r2libdirs += [join_paths(p, 'lib'), join_paths(p, 'radare2', 'lib')]
    endif
    r2libdirs += [meson.current_source_dir() + '/radare2/lib', 'C:/radare2/lib']

    rcore_lib = cc.find_library('r_core', dirs: r2libdirs, required: false)
    if not rcore_lib.found()
      rcore_lib = cc.find_library('libr_core', dirs: r2libdirs, required: false)
    endif

    if rcore_lib.found()
      incdirs = []
      if get_option('r2_prefix') != ''
        p = get_option('r2_prefix')
        incdirs += [join_paths(p, 'include', 'libr'), join_paths(p, 'include')]
      endif
      rcore_inc = include_directories(incdirs)
      r_core_dep = declare_dependency(dependencies: [rcore_lib], include_directories: rcore_inc)
      r2_libdirs = r2libdirs
      r2_incdirs = incdirs
    else
      error('Windows dependency lookup for r_core failed: ensure radare2 is installed and pass -Dr2_prefix=<prefix> (e.g. C:/radare2)')
    endif
  else
    r2_prefixes = []
    if get_option('r2_prefix') != ''
      r2_prefixes += [get_option('r2_prefix')]
    endif

    found = false
    foreach p : r2_prefixes
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
      extra_libdirs = libdirs + [join_paths(p, 'bin')]
      candidate_names = ['r_core', 'r_core-6', 'r_core6', 'r_core64', 'libr_core']
      foreach name : candidate_names
        rcore_lib = cc.find_library(name, dirs: extra_libdirs, required: false)
        if rcore_lib.found()
          rcore_inc = include_directories(incdirs + [join_paths(p, 'include', 'libr')])
          r_core_dep = declare_dependency(dependencies: [rcore_lib], include_directories: rcore_inc)
          r2_libdirs = extra_libdirs
          r2_incdirs = incdirs + [join_paths(p, 'include', 'libr')]
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

r_deps = {
  'r_util': ['r_util', 'libr_util'],
  'r_cons': ['r_cons', 'libr_cons'],
  'r_config': ['r_config', 'libr_config'],
  'r_socket': ['r_socket', 'libr_socket']
}

foreach dep_name, lib_names : r_deps
  dep_var = dependency(dep_name, method: 'pkg-config', required: false)
  if not dep_var.found() and r2_libdirs.length() > 0
    foreach name : lib_names
      lib = cc.find_library(name, dirs: r2_libdirs, required: false)
      if lib.found()
        inc = include_directories(r2_incdirs)
        dep_var = declare_dependency(dependencies: [lib], include_directories: inc)
        break
      endif
    endforeach
  endif
  if not dep_var.found()
    warning('@0@ dependency not found via pkg-config or same paths as r_core'.format(dep_name))
  endif
  set_variable(dep_name + '_dep', dep_var)
endforeach

# duplicated files between srcs and plugins, also "srcs" is not clear who will use that
srcs = [
  'src/main.c',
  'src/r2mcp.c',
  'src/readbuffer.c',
  'src/tools.c',
  'src/dsltest.c',
  'src/prompts.c',
  'src/jsonrpc.c',
]

plugin_srcs = [
  'src/plugin.c',
  'src/r2mcp.c',
  'src/readbuffer.c',
  'src/tools.c',
  'src/dsltest.c',
  'src/prompts.c',
  'src/jsonrpc.c',
]

if host_machine.system() == 'windows'
  configure_file(
    input: 'config.h.w64',
    output: 'config.h',
    copy: true
  )

  link_args = []
  c_args = []
  if cc.get_id() == 'msvc' or cc.get_id() == 'clang-cl'
    link_args += ['/SUBSYSTEM:CONSOLE', '/DEFAULTLIB:setupapi.lib']
  endif
else
  conf_data = configuration_data()
  conf_data.set('R2MCP_VERSION', meson.project_version())
  configure_file(
    input: 'src/config.h.acr',
    output: 'config.h',
    configuration: conf_data
  )
  link_args = []
  c_args = ['-D_GNU_SOURCE', '-D_POSIX_C_SOURCE=200809L']
endif

executable(
  'r2mcp',
  srcs,
  dependencies: [r_core_dep, r_util_dep, r_cons_dep, r_config_dep],
  c_args: c_args,
  link_args: link_args,
  install: true,
)

plugin_lib = shared_library(
  'core_r2mcp',
  plugin_srcs,
  dependencies: [r_core_dep, r_util_dep, r_cons_dep, r_config_dep],
  c_args: c_args,
  link_args: link_args,
  install: false,
)

executable(
  'r2mcp-svc',
  'svc/r2mcp-svc.c',
  dependencies: [r_socket_dep, r_util_dep, r_cons_dep],
  c_args: c_args,
  link_args: link_args,
  install: true,
)
