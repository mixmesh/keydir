-module(keydir_sup).
-behaviour(supervisor).
-export([start_link/0]).
-export([init/1]).

%% Exported: start_link

start_link() ->
    supervisor:start_link(?MODULE, []).

%% Exported: init

init([]) ->
    RemoteKeydirServerSpecs =
        case config:lookup(['remote-keydir-server', enabled]) of
            true ->
                [{RemoteKeydirServerAddress, RemoteKeydirServerPort},
                 Timeout, RemoteKeydirServerDataDir] =
                    config:lookup_children(
                      [address, timeout, 'data-dir'],
                      config:lookup(['remote-keydir-server'])),
                KeydirServSpec =
                    #{id => keydir_serv,
                      start => {keydir_serv, start_link,
                                [RemoteKeydirServerDataDir]}},
                KeydirNetworkServSpec =
                    #{id => keydir_network_serv,
                      start => {keydir_network_serv, start_link,
                                [RemoteKeydirServerAddress,
                                 RemoteKeydirServerPort,
                                 Timeout]}},
                [KeydirServSpec, KeydirNetworkServSpec];
            false ->
                []
        end,
    KeydirServiceSpecs =
        case config:lookup(['keydir-service', enabled]) of
            true ->
                [{KeydirServiceAddress, KeydirServicePort},
                 KeydirServiceDataDir] =
                    config:lookup_children([address, 'data-dir'],
                                           config:lookup(['keydir-service'])),
                KeydirServiceCertFilename =
                    filename:join([KeydirServiceDataDir, <<"ssl">>,
                                   <<"cert.pem">>]),
                [#{id => keydir_service,
                   start => {keydir_service, start_link,
                             [KeydirServiceAddress,
                              KeydirServicePort,
                              KeydirServiceCertFilename,
                              KeydirServiceDataDir]}}];
            false ->
                []
        end,
    {ok, {#{strategy => one_for_all},    
          RemoteKeydirServerSpecs ++ KeydirServiceSpecs}}.
