-module(keydir_sup).
-behaviour(supervisor).
-export([start_link/0]).
-export([init/1]).

%% Exported: start_link

start_link() ->
    supervisor:start_link(?MODULE, []).

%% Exported: init

init([]) ->
    case config:lookup(['remote-keydir-server', enabled]) of
        true ->
            [{Address, Port}, Timeout, RemoteKeydirDir, WebkeyService] =
                config:lookup_children(
                  [address, timeout, 'data-dir', 'webkey-service'],
                  config:lookup(['remote-keydir-server'])),
            KeydirServSpec =
                #{id => keydir_serv,
                  start => {keydir_serv, start_link, [RemoteKeydirDir]}},
            KeydirNetworkServSpec =
                #{id => keydir_network_serv,
                  start => {keydir_network_serv, start_link,
                            [Address, Port, Timeout]}},
            KeydirWebkeyServiceSpec =
                case config:lookup_children([enabled, address],
                                            WebkeyService) of
                    [true, {WebkeyServiceAddress, WebkeyServicePort}] ->
                        [MixmeshDir] =
                            config:lookup_children(
                              ['mixmesh-dir'], config:lookup([system])),
                        RemoteKeydirDir =
                            filename:join([MixmeshDir, <<"remote-keydir">>]),
                        CertFilename =
                            filename:join(
                              [RemoteKeydirDir, <<"ssl">>, <<"cert.pem">>]),
                        [#{id => keydir_webkey_service,
                           start => {keydir_webkey_service, start_link,
                                     [WebkeyServiceAddress,
                                      WebkeyServicePort,
                                      CertFilename]}}];
                    [false, _] ->
                        []
                end,
            {ok, {#{strategy => one_for_all},
                  [KeydirServSpec, KeydirNetworkServSpec] ++
                      KeydirWebkeyServiceSpec}};
        false ->
            {ok, {#{strategy => one_for_all}, []}}
    end.
