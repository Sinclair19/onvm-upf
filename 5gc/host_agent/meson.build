sources = files(
    'host_agent.c',
    'host_agent_config.c'
)

host_agent_c_args = [
  '-DDOCA_ALLOW_EXPERIMENTAL_API',
]

# DOCA 3.x split dependencies (control-path messaging to DPU)
# These dependency objects are provided by the parent 5gc/meson.build.
host_agent_link_deps = [
  doca_common_dep,
  doca_comch_dep,
]
