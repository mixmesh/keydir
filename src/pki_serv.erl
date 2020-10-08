-module(pki_serv).
-export([start_link/1, start_link/2, stop/0, stop/1]).
-export([create/1, create/2,
         read/1, read/2,
         update/1, update/2,
         delete/2, delete/3]).
-export([strerror/1]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("apptools/include/serv.hrl").
-include_lib("pki/include/pki_serv.hrl").

-record(state, {parent           :: pid(),
                db               :: ets:tid(),
                file_db          :: dets:tab_name(),
                top_level_server :: boolean()}).

%% Exported: start_link

-spec start_link(none | serv:name(), binary()) ->
          serv:spawn_server_result() |
          {error, {file_db_corrupt, any()}} | 
          {error, invalid_dir}.

start_link(Dir) ->
    ?spawn_server_opts(fun(Parent) -> init(Parent, Dir, true) end,
                       fun message_handler/1,
                       #serv_options{name = ?MODULE}).

start_link(none, Dir) ->
    ?spawn_server(fun(Parent) -> init(Parent, Dir, false) end,
                  fun message_handler/1);
start_link(PkiServName, Dir) ->
    ?spawn_server_opts(fun(Parent) -> init(Parent, Dir, false) end,
                       fun message_handler/1,
                       #serv_options{name = PkiServName}).

init(Parent, Dir, TopLevelServer) ->
    case filelib:is_dir(Dir) of
        true ->
            DbFilename = filename:join([Dir, <<"pki_db">>]),
            KeyPosition = #pki_user.name,
            case dets:open_file(
                   {file_db, self()},
                   [{file, ?b2l(DbFilename)}, {keypos, KeyPosition}]) of
                {ok, FileDb} ->
                    if
                        TopLevelServer ->
                            Db = ets:new(pki_db,
                                         [{keypos, KeyPosition}, named_table,
                                          {read_concurrency, true}, public]);
                        true ->
                            Db = ets:new(pki_db, [{keypos, KeyPosition}])
                    end,
                    true = ets:from_dets(Db, FileDb),
                    ?daemon_tag_log(system, "PKI server has been started: ~s",
                                    [Dir]),
                    {ok, #state{parent = Parent,
                                db = Db,
                                file_db = FileDb,
                                top_level_server = TopLevelServer}};
                {error, Reason} ->
                    {error, {file_db_corrupt, Reason}}
            end;
        false ->
            {error, invalid_dir}
    end.

%% Exported: stop

-spec stop(serv:name()) -> ok.

stop() ->
    stop(?MODULE).

stop(PkiServName) ->
    serv:cast(PkiServName, stop).

%% Exported: create

-spec create(serv:name(), #pki_user{}) -> ok | {error, user_already_exists}.

create(PkiUser) ->
    create(?MODULE, PkiUser).

create(PkiServName, PkiUser) ->
    serv:call(PkiServName, {create, PkiUser}).

%% Exported: read

-spec read(serv:name(), binary()) -> {ok, #pki_user{}} | {error, no_such_user}.

read(Name) ->
    %% NOTE: A top-level PKI server uses a public and named table
    case ets:lookup(pki_db, Name)  of
        [] ->
            {error, no_such_user};
        [PkiUser] ->
            {ok, PkiUser}
    end.

read(PkiServName, Name) ->
    serv:call(PkiServName, {read, Name}).

%% Exported: update

-spec update(serv:name(), #pki_user{}) ->
          ok | {error, no_such_user | permission_denied}.

update(PkiUser) ->
    update(?MODULE, PkiUser).

update(PkiServName, PkiUser) ->
    serv:call(PkiServName, {update, PkiUser}).

%% Exported: update

-spec delete(serv:name(), binary(), binary()) ->
          ok | {error, no_such_user | permission_denied}.

delete(Name, Password) ->
    delete(?MODULE, Name, Password).

delete(PkiServName, Name, Password) ->
    serv:call(PkiServName, {delete, Name, Password}).

%% Exported: strerror

-spec strerror({file_db_corrupt, any()} |
               invalid_dir |
               user_already_exists |
               no_such_user |
               permission_denied |
               {unknown_error, any()}) -> binary().

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
        {cast, stop} ->
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
        {call, From, {read, Name}} ->
            case ets:lookup(Db, Name)  of
                [] ->
                    {reply, From, {error, no_such_user}};
                [PkiUser] ->
                    {reply, From, {ok, PkiUser}}
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
