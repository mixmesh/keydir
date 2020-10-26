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
            [{Address, Port}, Timeout, DataDir] =
                config:lookup_children([address, timeout, 'data-dir'],
                                       config:lookup(['global-pki-server'])),
            PkiServSpec =
                #{id => pki_serv,
                  start => {pki_serv, start_link, [DataDir]}},
            PkiNetworkServSpec =
                #{id => pki_network_serv,
                  start => {pki_network_serv, start_link,
                            [Address, Port, Timeout]}},
            {ok, {#{strategy => one_for_all}, [PkiServSpec,
                                               PkiNetworkServSpec]}};
        false ->
            {ok, {#{strategy => one_for_all}, []}}
    end.
