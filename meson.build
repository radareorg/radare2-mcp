project(
  'r2mcp',
  'c',
  version : '1.2.0',
)

cc = meson.get_compiler('c')

# radare2 core dependency via pkg-config (mirrors Makefile's pkg-config r_core)
r_core_dep = dependency('r_core', required: true)

# Match Makefile warning flags when using gcc/clang
c_args = []
if cc.get_id() == 'gcc' or cc.get_id() == 'clang'
  c_args += ['-Wall', '-Wextra']
endif

srcs = [
  'main.c',
  'r2mcp.c',
  'readbuffer.c',
  'tools.c',
  'prompts.c',
]

executable(
  'r2mcp',
  srcs,
  dependencies: [r_core_dep],
  c_args: c_args,
  install: true,
)
