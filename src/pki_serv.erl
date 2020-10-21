-module(pki_serv).
-export([start_link/2, stop/0, stop/1]).
-export([create/1, create/2,
         read/1, read/2,
         update/1, update/2,
         delete/2, delete/3]).
-export([strerror/1]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("apptools/include/serv.hrl").
-include("../include/pki_serv.hrl").

-type pki_mode() :: global | local.
-record(state, {parent :: pid(),
                db :: ets:tid(),
                shared_key :: binary(),
                db_filename :: binary(),
                fd :: file:io_device(),
                mode :: pki_mode()}).

%% Exported: start_link

-spec start_link(pki_mode(), binary()) ->
          serv:spawn_server_result() |
          {error, {file_error, any()}} |
          {error, invalid_dir}.

start_link(global, Dir) ->
    ?spawn_server_opts(fun(Parent) -> init(Parent, Dir, global) end,
                       fun message_handler/1,
                       #serv_options{name = ?MODULE});
start_link(local, Dir) ->
    ?spawn_server(fun(Parent) -> init(Parent, Dir, local) end,
                  fun message_handler/1).

init(Parent, Dir, Mode) ->
    case filelib:is_dir(Dir) of
        true ->
            DbFilename = filename:join([Dir, <<"pki.db">>]),
            ok = copy_file(Mode, DbFilename),
            case file:open(DbFilename, [read, write, binary]) of
                {ok, Fd} ->
                    KeyPosition = #pki_user.nym,
                    case Mode of
                        global ->
                            Db = ets:new(pki_db,
                                         [{keypos, KeyPosition}, named_table,
                                          {read_concurrency, true}, public]);
                        local ->
                            Db = ets:new(pki_db, [{keypos, KeyPosition}])
                    end,
                    [Pin, PinSalt] =
                        config:lookup_children(
                          [pin, 'pin-salt'], config:lookup([])),
                    SharedKey = player_crypto:pin_to_shared_key(Pin, PinSalt),
                    ok = import_file(Fd, Db, SharedKey),
                    ?daemon_log_tag_fmt(
                       system, "PKI server has been started: ~s", [Dir]),
                    {ok, #state{parent = Parent,
                                db = Db,
                                shared_key = SharedKey,
                                db_filename = DbFilename,
                                fd = Fd,
                                mode = Mode}};
                {error, Reason} ->
                    {error, {file_error, Reason}}
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

read(Nym) ->
    case ets:lookup(pki_db, Nym)  of
        [] ->
            {error, no_such_user};
        [PkiUser] ->
            {ok, PkiUser}
    end.

read(PkiServName, Nym) ->
    serv:call(PkiServName, {read, Nym}).

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

delete(Nym, Password) ->
    delete(?MODULE, Nym, Password).

delete(PkiServName, Nym, Password) ->
    serv:call(PkiServName, {delete, Nym, Password}).

%% Exported: strerror

-spec strerror({file_error, any()} |
               invalid_dir |
               user_already_exists |
               no_such_user |
               permission_denied |
               {unknown_error, any()}) -> binary().

strerror({file_error, Reason}) ->
    ?error_log({file_error, Reason}),
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

message_handler(#state{parent = Parent,
                       db = Db,
                       shared_key = SharedKey,
                       db_filename = DbFilename,
                       fd = Fd} = State) ->
    receive
        {cast, stop} ->
            file:close(Fd),
            stop;
        {call, From, {create, PkiUser}} ->
            case ets:lookup(Db, PkiUser#pki_user.nym) of
                [_] ->
                    {reply, From, {error, user_already_exists}};
                [] ->
                    true = ets:insert(Db, PkiUser),
                    ok = file:write(Fd, pack(PkiUser, SharedKey)),
                    ok = file:sync(Fd),
                    {reply, From, ok}
            end;
        {call, From, {read, Nym}} ->
            case ets:lookup(Db, Nym)  of
                [] ->
                    {reply, From, {error, no_such_user}};
                [PkiUser] ->
                    {reply, From, {ok, PkiUser}}
            end;
        {call, From, {update, #pki_user{nym = Nym,
                                       password = Password} = PkiUser}} ->
            case ets:lookup(Db, Nym) of
                [] ->
                    {reply, From, {error, no_such_user}};
                [#pki_user{password = Password}] ->
                    true = ets:insert(Db, PkiUser),
                    file:close(Fd),
                    {ok, NewFd} = export_file(Db, DbFilename, SharedKey),
                    {reply, From, ok, State#state{fd = NewFd}};
                [_] ->
                    {reply, From, {error, permission_denied}}
            end;
        {call, From, {delete, Nym, Password}} ->
            case ets:lookup(Db, Nym) of
                [] ->
                    {reply, From, {error, no_such_user}};
                [#pki_user{password = Password}] ->
                    true = ets:delete(Db, Nym),
                    file:close(Fd),
                    {ok, NewFd} = export_file(Db, DbFilename, SharedKey),
                    {reply, From, ok, State#state{fd = NewFd}};
                [_] ->
                    {reply, From, {error, permission_denied}}
            end;
        {system, From, Request} ->
            {system, From, Request};
        {'EXIT', Parent, Reason} ->
            file:close(Fd),
            exit(Reason);
        UnknownMessage ->
            ?error_log({unknown_message, UnknownMessage}),
            noreply
    end.

copy_file(global, _DbFilename) ->
    ok;
copy_file(local, DbFilename) ->
    %% note must have a default of false, simulator may not always be present!
    case config:lookup([simulator, enabled], false) of
        true ->
            PrePopulatedDbFilename =
                filename:join([code:priv_dir(simulator),
                               config:lookup([simulator, 'data-set']),
                               <<"pki.db">>]),
            case file:copy(PrePopulatedDbFilename, DbFilename) of
                {ok, _BytesCopied} ->
                    ?daemon_log_tag_fmt(
                       system, "Copied PKI database file from ~s",
                       [PrePopulatedDbFilename]);
                {error, Reason} ->
                    ?daemon_log_tag_fmt(
                       system,
                       "WARNING: Could not copy PKI database file from ~s: ~s",
                       [DbFilename, inet:format_error(Reason)])
            end,
            ok;
        false ->
            ok
    end.

pack(#pki_user{nym = Nym,
               password = Password,
               email = Email,
               public_key = PublicKey}, SharedKey) ->
    Nonce = enacl:randombytes(enacl:secretbox_NONCEBYTES()),
    NonceSize = size(Nonce),
    NymSize = size(Nym),
    PasswordSize = size(Password),
    EmailSize = size(Email),
    PublicKeyBin = elgamal:public_key_to_binary(PublicKey),
    PublicKeyBinSize = size(PublicKeyBin),
    Entry =
        <<NymSize:16/unsigned-integer,
          Nym/binary,
          PasswordSize:16/unsigned-integer,
          Password/binary,
          EmailSize:16/unsigned-integer,
          Email/binary,
          PublicKeyBinSize:16/unsigned-integer,
          PublicKeyBin/binary>>,
    EncryptedEntry = enacl:secretbox(Entry, Nonce, SharedKey),
    EncryptedEntrySize = size(EncryptedEntry),
    <<NonceSize:16/unsigned-integer,
      Nonce/binary,
      EncryptedEntrySize:16/unsigned-integer,
      EncryptedEntry/binary>>.

import_file(Fd, Db, SharedKey) ->
    case file:read(Fd, 2) of
        eof ->
            ok;
        {ok, <<NonceSize:16/unsigned-integer>>} ->
            {ok, Nonce} = file:read(Fd, NonceSize),
            {ok, <<EncryptedEntrySize:16/unsigned-integer>>} = file:read(Fd, 2),
            {ok, EncryptedEntry} = file:read(Fd, EncryptedEntrySize),
            {ok, <<NymSize:16/unsigned-integer,
                   Nym:NymSize/binary,
                   PasswordSize:16/unsigned-integer,
                   Password:PasswordSize/binary,
                   EmailSize:16/unsigned-integer,
                   Email:EmailSize/binary,
                   PublicKeySize:16/unsigned-integer,
                   PublicKey:PublicKeySize/binary>>} =
                enacl:secretbox_open(EncryptedEntry, Nonce, SharedKey),
            PkiUser =
                #pki_user{nym = Nym,
                          password = Password,
                          email = Email,
                          public_key = elgamal:binary_to_public_key(PublicKey)},
            true = ets:insert(Db, PkiUser),
            import_file(Fd, Db, SharedKey);
        {error, Reason} ->
            {error, Reason}
    end.

export_file(Db, DbFilename, SharedKey) ->
    _ = file:delete(DbFilename),
    {ok, Fd} = file:open(DbFilename, [read, write, binary]),
    ok = ets:foldl(fun(PkiUser, ok) ->
                           file:write(Fd, pack(PkiUser, SharedKey))
                   end, ok, Db),
    ok = file:sync(Fd),
    {ok, Fd}.
