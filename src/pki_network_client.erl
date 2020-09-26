-module(pki_network_client).
-export([create/1, create/2]).
-export([read/1, read/2]).
-export([update/1, update/2]).
-export([delete/2, delete/3]).
-export([alive/1, alive/2]).
-export([recv/3, send/2]).

-include_lib("apptools/include/log.hrl").
-include("pki_network.hrl").

-define(TOR_HOSTNAME , "z2rev4qfooicn3z3.onion").
%%-define(DIRECT_HOSTNAME, "mother.tplinkdns.com").
-define(DIRECT_HOSTNAME, "127.0.0.1").
-define(PORT, 11112).
-define(TIMEOUT, 30000).
%%-define(EXTRA_OPTIONS, [{pki_mode, fallback_to_direct_access}]).
%%-define(EXTRA_OPTIONS, [{pki_mode, tor_access_only}]).
-define(EXTRA_OPTIONS, [{pki_mode, direct_access_only}]).

%% Exported: create

create(User) ->
    create(?TIMEOUT, User).

create(Timeout, User) ->
    ?dbg_log({create, Timeout, User}),
    case connect([binary, {active, false}] ++ ?EXTRA_OPTIONS, Timeout) of
        {ok, Transport} ->
            try
                ok = pki_util:write_integer(1, Transport, ?CREATE),
                ok = pki_util:write_user(Transport, User),
                case pki_util:read_integer(1, Transport, Timeout) of
                    ?OK ->
                        ok;
                    ?ERROR ->
                        Reason = pki_util:read_binary(2, Transport, Timeout),
                        {error, Reason}
                end
            catch
                throw:{pki_util, PkiUtilReason} ->
                    close(Transport),
                    {error, PkiUtilReason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% Exported: read

read(Name) ->
    read(?TIMEOUT, Name).

read(Timeout, Name) ->
    ?dbg_log({read, Timeout, Name}),
    case connect([binary, {active, false}] ++ ?EXTRA_OPTIONS, Timeout) of
        {ok, Transport} ->
            try
                ok = pki_util:write_integer(1, Transport, ?READ),
                ok = pki_util:write_binary(1, Transport, Name),
                case pki_util:read_integer(1, Transport, Timeout) of
                    ?OK ->
                        User = pki_util:read_user(Transport, Timeout),
                        {ok, User};
                    ?ERROR ->
                        Reason = pki_util:read_binary(2, Transport, Timeout),
                        {error, Reason}
                end
            catch
                throw:{pki_util, PkiUtilReason} ->
                    close(Transport),
                    {error, PkiUtilReason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% Exported: update

update(User) ->
    update(?TIMEOUT, User).

update(Timeout, User) ->
    ?dbg_log({update, Timeout, User}),
    case connect([binary, {active, false}] ++ ?EXTRA_OPTIONS, Timeout)  of
        {ok, Transport} ->
            try
                ok = pki_util:write_integer(1, Transport, ?UPDATE),
                ok = pki_util:write_user(Transport, User),
                case pki_util:read_integer(1, Transport, Timeout) of
                    ?OK ->
                        ok;
                    ?ERROR ->
                        Reason = pki_util:read_binary(2, Transport, Timeout),
                        {error, Reason}
                end
            catch
                throw:{pki_util, PkiUtilReason} ->
                    close(Transport),
                    {error, PkiUtilReason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% Exported: delete

delete(Name, Password) ->
    delete(?TIMEOUT, Name, Password).

delete(Timeout, Name, Password) ->
    ?dbg_log({delete, Timeout, Name, Password}),
    case connect([binary, {active, false}] ++ ?EXTRA_OPTIONS, Timeout) of
        {ok, Transport} ->
            try
                ok = pki_util:write_integer(1, Transport, ?DELETE),
                ok = pki_util:write_binary(1, Transport, Name),
                ok = pki_util:write_binary(1, Transport, Password),
                case pki_util:read_integer(1, Transport, Timeout) of
                    ?OK ->
                        ok;
                    ?ERROR ->
                        Reason = pki_util:read_binary(2, Transport, Timeout),
                        {error, Reason}
                end
            catch
                throw:{pki_util, PkiUtilReason} ->
                    close(Transport),
                    {error, PkiUtilReason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% Exported: alive

alive(Transport) ->
    alive(Transport, ?TIMEOUT).

alive(Transport, Timeout) ->
    ?dbg_log(ping),
    try
        ok = pki_util:write_integer(1, Transport, ?PING),
        ?PONG = pki_util:read_integer(1, Transport, Timeout),
        ?dbg_log(pong),
        true
    catch
        throw:{pki_util, _Reason} ->
            false
    end.

%%
%% Transport primitives
%%

connect(Options, Timeout) ->
    Transport = get(pki_transport),
    case Transport /= undefined andalso alive(Transport, Timeout) of
        true ->
            {ok, Transport};
        false ->
            case lists:keysearch(pki_mode, 1, Options) of
                {value, {_, PkiMode}} ->
                    ok;
                false ->
                    PkiMode = tor_access_only
            end,
            NewOptions = lists:keydelete(pki_mode, 1, Options),
            case PkiMode of
                tor_access_only ->
                    case tor_socks_tcp:connect(
                           ?TOR_HOSTNAME, ?PORT, NewOptions, Timeout) of
                        {ok, Pid} ->
                            NewTransport = {socks, Pid},
                            put(pki_transport, NewTransport),
                            {ok, NewTransport};
                        {error, Reason} ->
                            {error, Reason}
                    end;
                direct_access_only ->
                    %% NOTE: We should use SSL here but that is a mandatory TODO
                    %% item for later
                    case gen_tcp:connect(
                           ?DIRECT_HOSTNAME, ?PORT, NewOptions, Timeout) of
                        {ok, Socket} ->
                            NewTransport = Socket,
                            put(pki_transport, NewTransport),
                            {ok, NewTransport};
                        {error, Reason} ->
                            {error, Reason}
                    end;
                fallback_to_direct_access ->
                    %% NOTE: We should fallback to SSL but that is a mandatory
                    %% TODO item for later
                    case tor_socks_tcp:connect(
                           ?TOR_HOSTNAME, ?PORT, NewOptions, Timeout) of
                        {ok, Pid} ->
                            NewTransport = {socks, Pid},
                            put(pki_transport, NewTransport),
                            {ok, NewTransport};
                        {error, _Reason} ->
                            case gen_tcp:connect(
                                   ?DIRECT_HOSTNAME, ?PORT, NewOptions,
                                   Timeout) of
                                {ok, Socket} ->
                                    NewTransport = Socket,
                                    put(pki_transport, NewTransport),
                                    ?daemon_tag_log(
                                      system,
                                      <<"WARNING: Falls back to direct access">>,
                                      []),
                                    {ok, NewTransport};
                                {error, Reason} ->
                                    {error, Reason}
                            end
                    end
            end
    end.

close({socks, Pid}) ->
    erase(pki_transport),
    tor_socks_tcp:close(Pid);
close(Socket) ->
    erase(pki_transport),
    gen_tcp:close(Socket).

%% Exported: recv

recv({socks, Pid}, Length, Timeout) ->
    tor_socks_tcp:recv(Pid, Length, Timeout);
recv(Socket, Length, Timeout) ->
    gen_tcp:recv(Socket, Length, Timeout).

%% Exported: send

send({socks, Pid}, Packet) ->
    tor_socks_tcp:send(Pid, Packet);
send(Socket, Packet) ->
    gen_tcp:send(Socket, Packet).
