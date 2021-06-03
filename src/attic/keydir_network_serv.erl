-module(keydir_network_serv).
-export([start_link/3, stop/1]).
-export([message_handler/1]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/serv.hrl").
-include("../include/keydir_serv.hrl").
-include("keydir_network.hrl").

-record(state, {parent :: pid(),
                timeout :: timeout(),
                listen_socket :: inet:socket(),
                acceptors :: [pid()]}).

%% Exported: start_link

start_link(Address, Port, Timeout) ->
    ?spawn_server(
       fun(Parent) ->
               init(Parent, Address, Port, Timeout)
       end,
       fun ?MODULE:message_handler/1).

%% Exported: stop

stop(Pid) ->
    serv:call(Pid, stop).

%%
%% Server
%%

init(Parent, Address, Port, Timeout) ->
    {ok, ListenSocket} =
        gen_tcp:listen(Port, [{active, false}, {ip, Address}, {reuseaddr, true},
                              binary]),
    self() ! accepted,
    ?daemon_log_tag_fmt(system, "Keydir TCP server has been started on ~s:~w",
                        [inet:ntoa(Address), Port]),
    {ok, #state{parent = Parent,
                timeout = Timeout,
                listen_socket = ListenSocket,
                acceptors = []}}.

message_handler(
  #state{parent = Parent,
         timeout = Timeout,
         listen_socket = ListenSocket,
         acceptors = Acceptors} = State) ->
    receive
        {call, From, stop} ->
            ok = gen_tcp:close(ListenSocket),
            {stop, From, ok};
        accepted ->
            Owner = self(),
            Pid =
                proc_lib:spawn_link(
                  fun() ->
                          acceptor(Owner, Timeout, ListenSocket)
                  end),
            {noreply, State#state{acceptors = [Pid|Acceptors]}};
        {system, From, Request} ->
            {system, From, Request};
        {'EXIT', Parent, Reason} ->
            ok = gen_tcp:close(ListenSocket),
            exit(Reason);
        {'EXIT', Pid, normal} ->
            case lists:member(Pid, Acceptors) of
                true ->
                    {noreply,
                     State#state{acceptors = lists:delete(Pid, Acceptors)}};
                false ->
                    ?error_log({not_an_acceptor, Pid}),
                    noreply
            end;
        UnknownMessage ->
            ?error_log({unknown_message, UnknownMessage}),
            noreply
    end.

acceptor(Owner, Timeout, ListenSocket) ->
    {ok, Socket} = gen_tcp:accept(ListenSocket),
    Owner ! accepted,
    case read_request(Socket, Timeout) of
        {error, closed} ->
            ok;
        {error, _Reason} ->
            gen_tcp:close(Socket)
    end.

%%
%% Read request
%%

read_request(Socket, Timeout) ->
    case read_method(Socket, Timeout) of
        {ok, ?CREATE} ->
            ?dbg_log(create),
            try
                KeydirUser = keydir_util:read_user(Socket, Timeout),
                case keydir_serv:create(KeydirUser) of
                    ok ->
                        ok = keydir_util:write_integer(1, Socket, ?OK);
                    {error, Reason} ->
                        ok = keydir_util:write_integer(1, Socket, ?ERROR),
                        ok = keydir_util:write_binary(
                               2, Socket, keydir_serv:strerror(Reason))
                end
            catch
                throw:{?MODULE, ThrowReason} ->
                    ?error_log({create, ThrowReason}),
                    keydir_util:write_integer(1, Socket, ?ERROR),
                    keydir_util:write_binary(2, Socket, <<"Invalid request">>)
            end,
            read_request(Socket, Timeout);
        {ok, ?READ} ->
            ?dbg_log(read),
            try
                Name = keydir_util:read_binary(1, Socket, Timeout),
                case keydir_serv:read(Name)  of
                    {ok, KeydirUser} ->
                        ok = keydir_util:write_integer(1, Socket, ?OK),
                        keydir_util:write_user(Socket, KeydirUser#keydir_user{
                                                         password = <<>>,
                                                         email = <<>>});
                    {error, Reason} ->
                        ok = keydir_util:write_integer(1, Socket, ?ERROR),
                        keydir_util:write_binary(2, Socket,
                                                 keydir_serv:strerror(Reason))
                end
            catch
                throw:{?MODULE, ThrowReason} ->
                    ?error_log({create, ThrowReason}),
                    keydir_util:write_integer(1, Socket, ?ERROR),
                    keydir_util:write_binary(2, Socket, <<"Invalid request">>)
            end,
            read_request(Socket, Timeout);
        {ok, ?UPDATE} ->
            ?dbg_log(update),
            try
                KeydirUser = keydir_util:read_user(Socket, Timeout),
                case keydir_serv:update(KeydirUser) of
                    ok ->
                        ok = keydir_util:write_integer(1, Socket, ?OK);
                    {error, Reason} ->
                        ok = keydir_util:write_integer(1, Socket, ?ERROR),
                        ok = keydir_util:write_binary(
                               2, Socket, keydir_serv:strerror(Reason))
                end
            catch
                throw:{?MODULE, ThrowReason} ->
                    ?error_log({update, ThrowReason}),
                    keydir_util:write_integer(1, Socket, ?ERROR),
                    keydir_util:write_binary(2, Socket, <<"Invalid request">>)
            end,
            read_request(Socket, Timeout);
        {ok, ?DELETE} ->
            ?dbg_log(delete),
            try
                Name = keydir_util:read_binary(1, Socket, Timeout),
                Password = keydir_util:read_binary(1, Socket, Timeout),
                case keydir_serv:delete(Name, Password) of
                    ok ->
                        ok = keydir_util:write_integer(1, Socket, ?OK);
                    {error, Reason} ->
                        ok = keydir_util:write_integer(1, Socket, ?ERROR),
                        ok = keydir_util:write_binary(
                               2, Socket, keydir_serv:strerror(Reason))
                end
            catch
                throw:{?MODULE, ThrowReason} ->
                    ?error_log({update, ThrowReason}),
                    keydir_util:write_integer(1, Socket, ?ERROR),
                    keydir_util:write_binary(2, Socket, <<"Invalid request">>)
            end,
            read_request(Socket, Timeout);
        {ok, ?PING} ->
            ?dbg_log(ping),
            ok = keydir_util:write_integer(1, Socket, ?PONG),
            read_request(Socket, Timeout);
        {ok, Method} ->
            ?error_log({unknown_method, Method}),
            keydir_util:write_integer(1, Socket, ?ERROR),
            keydir_util:write_binary(2, Socket, <<"Unknown method">>),
            read_request(Socket, Timeout);
        {error, Reason} ->
            {error, Reason}
    end.

read_method(Transport, Timeout) ->
    case keydir_network_client:recv(Transport, 1, Timeout) of
        {ok, <<Method>>} ->
            {ok, Method};
        {error, Reason} ->
            {error, Reason}
    end.
