-module(global_pki_server_schema).
-export([get/0]).

-include_lib("apptools/include/config_schema.hrl").

get() ->
    [{'global-pki-server',
      [{enabled,
        #json_type{
           name = bool,
           typical = false,
           reloadable = false}},
       {address,
        #json_type{
           name = ipv4address_port,
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
           typical = <<"/var/obscrete/pki/data">>,
           reloadable = false}}]}].
