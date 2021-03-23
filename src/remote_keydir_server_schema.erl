-module(remote_keydir_server_schema).
-export([get/0]).

-include_lib("apptools/include/config_schema.hrl").

get() ->
    [{'remote-keydir-server',
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
       {timeout,
        #json_type{
           name = {integer, 0, unbounded},
           typical = 10000,
           reloadable = false}},
       {'data-dir',
        #json_type{
           name = writable_directory,
           typical = <<"/var/mixmesh/keydir/data">>,
           reloadable = false}},
       {'webkey-service',
        [{enabled,
          #json_type{
             name = bool,
             typical = false,
             reloadable = false}},
         {address,
          #json_type{
             name = ip4_address_port,
             typical = {{127, 0, 0, 1}, 10001},
             reloadable = false}}]}]}].