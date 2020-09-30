-module(pki_serv).
-export([start_link/1, stop/0]).
-export([create/1, read/1, update/1, delete/2]).
-export([strerror/1]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("apptools/include/serv.hrl").
-include_lib("pki/include/pki_serv.hrl").

-record(state, {%% pid()
                parent,
                %% tid()
                db,
                %% dets:tab_name()
                file_db}).

%% Exported: start_link

start_link(Dir) ->
    ?spawn_server_opts(fun(Parent) -> init(Parent, Dir) end,
                       fun message_handler/1,
                       #serv_options{name = ?MODULE}).

init(Parent, Dir) ->
    case filelib:is_dir(Dir) of
        true ->
            DbFilename = filename:join([Dir, <<"pki_db">>]),
            KeyPosition = #pki_user.name,
            case dets:open_file({file_db, self()},
                                [{file, ?b2l(DbFilename)}, {keypos, KeyPosition}]) of
                {ok, FileDb} ->
                    Db = ets:new(pki_db, [{keypos, KeyPosition}, named_table,
                                          {read_concurrency, true}, public]),
                    true = ets:from_dets(Db, FileDb),
                    ?daemon_tag_log(system, "PKI server has been started: ~s", [Dir]),
                    {ok, #state{parent = Parent, db = Db, file_db = FileDb}};
                {error, Reason} ->
                    {error, {file_db_corrupt, Reason}}
            end;
        false ->
            {error, invalid_dir}
    end.

%% Exported: stop

stop() ->
  ?MODULE ! stop,
  ok.

%% Exported: create

create(PkiUser) ->
    serv:call(?MODULE, {create, PkiUser}).

%% Exported: read

read(Name) ->
    case ets:lookup(pki_db, Name)  of
        [] ->
            {error, no_such_user};
        [PkiUser] ->
            {ok, PkiUser}
    end.

%% Exported: update

update(PkiUser) ->
  serv:call(?MODULE, {update, PkiUser}).

%% Exported: update

delete(Name, Password) ->
  serv:call(?MODULE, {delete, Name, Password}).

%% Exported: strerror

strerror({file_db_corrupt, FileDbReason}) ->
    ?error_log({file_db_corrupt, FileDbReason}),
    <<"PKI database is corrupt">>;
strerror(invalid_dir) ->
    <<"PKI directory is invalid">>;
strerror(user_already_exists) ->
    <<"User already exists">>;
strerror(no_such_user) ->
    <<"No such user">>;
strerror(permission_denied) ->
    <<"Permission denied">>;
strerror(Reason) ->
    ?error_log({unknown_error, Reason}),
    <<"Internal error">>.

%%
%% Message handler
%%

message_handler(#state{parent = Parent, db = Db, file_db = FileDb}) ->
    receive
        stop ->
            stop;
        {call, From, {create, PkiUser}} ->
            case ets:lookup(Db, PkiUser#pki_user.name) of
                [_] ->
                    {reply, From, {error, user_already_exists}};
                [] ->
                    true = ets:insert(Db, PkiUser),
                    ok = dets:insert(FileDb, PkiUser),
                    {reply, From, ok}
            end;
        {call, From, {update, #pki_user{name = Name,
                                       password = Password} = PkiUser}} ->
            case ets:lookup(Db, Name) of
                [] ->
                    {reply, From, {error, no_such_user}};
                [#pki_user{password = Password}] ->
                    true = ets:insert(Db, PkiUser),
                    ok = dets:insert(FileDb, PkiUser),
                    {reply, From, ok};
                [_] ->
                    {reply, From, {error, permission_denied}}
            end;
        {call, From, {delete, Name, Password}} ->
            case ets:lookup(Db, Name) of
                [] ->
                    {reply, From, {error, no_such_user}};
                [#pki_user{password = Password}] ->
                    true = ets:delete(Db, Name),
                    ok = dets:delete(FileDb, Name),
                    {reply, From, ok};
                [_] ->
                    {reply, From, {error, permission_denied}}
            end;
        {system, From, Request} ->
            {system, From, Request};
        {'EXIT', Parent, Reason} ->
            exit(Reason);
        UnknownMessage ->
            ?error_log({unknown_message, UnknownMessage}),
            noreply
    end.
