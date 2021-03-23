-module(pki_sup).
-behaviour(supervisor).
-export([start_link/0]).
-export([init/1]).

%% Exported: start_link

start_link() ->
    supervisor:start_link(?MODULE, []).

%% Exported: init

init([]) ->
    case config:lookup(['global-pki-server', enabled]) of
        true ->
            [{Address, Port}, Timeout, GlobalPkiDir, WebkeyService] =
                config:lookup_children(
                  [address, timeout, 'data-dir', 'webkey-service'],
                  config:lookup(['global-pki-server'])),
            PkiServSpec =
                #{id => pki_serv,
                  start => {pki_serv, start_link, [GlobalPkiDir]}},
            PkiNetworkServSpec =
                #{id => pki_network_serv,
                  start => {pki_network_serv, start_link,
                            [Address, Port, Timeout]}},
            PkiWebkeyServiceSpec =
                case config:lookup_children([enabled, address], WebkeyService) of
                    [true, {WebkeyServiceAddress, WebkeyServicePort}] ->
                        [MixmeshDir] =
                            config:lookup_children(
                              ['mixmesh-dir'], config:lookup([system])),
                        GlobalPkiDir =
                            filename:join([MixmeshDir, <<"global-pki">>]),
                        CertFilename =
                            filename:join(
                              [GlobalPkiDir, <<"ssl">>, <<"cert.pem">>]),
                        [#{id => pki_webkey_service,
                           start => {pki_webkey_service, start_link,
                                     [WebkeyServiceAddress,
                                      WebkeyServicePort,
                                      CertFilename]}}];
                    [false, _] ->
                        []
                end,
            {ok, {#{strategy => one_for_all},
                  [PkiServSpec, PkiNetworkServSpec] ++ PkiWebkeyServiceSpec}};
        false ->
            {ok, {#{strategy => one_for_all}, []}}
    end.
