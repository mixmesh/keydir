-module(keydir_service_schema).
-export([get/0]).

-include_lib("apptools/include/config_schema.hrl").

get() ->
    [{'keydir-service',
      [{enabled,
        #json_type{
           name = bool,
           typical = false,
           reloadable = false}},
       {address,
        #json_type{
           name = ip4_address_port,
           typical = {{127, 0, 0, 1}, 10000},
           reloadable = false}},
       {'data-dir',
        #json_type{
           name = writable_directory,
           typical = <<"/var/mixmesh/keydir-service">>,
           reloadable = false}}]}].
