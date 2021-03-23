-module(keydir_serv).
-export([start_link/1, stop/0]).
-export([create/1, read/1, update/1, delete/2, list/2]).
-export([strerror/1]).
-export([message_handler/1]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("apptools/include/serv.hrl").
-include("../include/keydir_serv.hrl").

-record(state, {parent :: pid(),
                db :: ets:tid(),
                shared_key :: binary(),
                db_filename :: binary(),
                fd :: file:io_device()}).

%% Exported: start_link

-spec start_link(binary()) ->
          serv:spawn_server_result() |
          {error, {file_error, any()}}.

start_link(RemoteKeydirDir) ->
    ?spawn_server_opts(fun(Parent) -> init(Parent, RemoteKeydirDir) end,
                       fun ?MODULE:message_handler/1,
                       #serv_options{name = ?MODULE}).

init(Parent, RemoteKeydirDir) ->
    DbFilename = filename:join([RemoteKeydirDir, <<"keydir.db">>]),
    ok = copy_file(DbFilename),
    case file:open(DbFilename, [read, write, binary]) of
        {ok, Fd} ->
            KeyPosition = #keydir_user.nym,
            Db = ets:new(keydir_db,
                         [ordered_set, {keypos, KeyPosition},
                          public, named_table,
                          {read_concurrency, true}]),
            MixmeshDir = config:lookup([system, 'mixmesh-dir']),
            PinFilename = filename:join([MixmeshDir, <<"pin">>]),
            {ok, Pin} = file:read_file(PinFilename),
            PinSalt = config:lookup([system, 'pin-salt']),
            SharedKey = player_crypto:pin_to_shared_key(Pin, PinSalt),
            ok = import_file(Fd, Db, SharedKey),
            ?daemon_log_tag_fmt(
               system, "Remote Keydir server has been started: ~s",
               [RemoteKeydirDir]),
            {ok, #state{parent = Parent,
                        db = Db,
                        shared_key = SharedKey,
                        db_filename = DbFilename,
                        fd = Fd}};
        {error, Reason} ->
            {error, {file_error, Reason}}
    end.

%% Exported: stop

-spec stop() -> ok.

stop() ->
    serv:cast(?MODULE, stop).

%% Exported: create

-spec create(#keydir_user{}) -> ok | {error, user_already_exists}.

create(KeydirUser) ->
    serv:call(?MODULE, {create, KeydirUser}).

%% Exported: read

-spec read(binary()) -> {ok, #keydir_user{}} | {error, no_such_user}.

read(Nym) ->
    case ets:lookup(keydir_db, Nym)  of
        [] ->
            {error, no_such_user};
        [KeydirUser] ->
            {ok, KeydirUser}
    end.

%% Exported: update

-spec update(#keydir_user{}) ->
          ok | {error, no_such_user | permission_denied}.

update(KeydirUser) ->
    serv:call(?MODULE, {update, KeydirUser}).

%% Exported: delete

-spec delete(binary(), binary()) ->
          ok | {error, no_such_user | permission_denied}.

delete(Nym, Password) ->
    serv:call(?MODULE, {delete, Nym, Password}).

%% Exported: list

-spec list({substring, binary()} | all, non_neg_integer()) ->
          {ok, [#keydir_user{}]}.

list(NymPattern, N) ->
    serv:call(?MODULE, {list, NymPattern, N}).

%% Exported: strerror

-spec strerror({file_error, any()} |
               user_already_exists |
               no_such_user |
               permission_denied |
               {unknown_error, any()}) -> binary().

strerror({file_error, Reason}) ->
    ?error_log({file_error, Reason}),
    <<"Keydir database is corrupt">>;
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
        {call, From, {create, KeydirUser}} ->
            case ets:lookup(Db, KeydirUser#keydir_user.nym) of
                [_] ->
                    {reply, From, {error, user_already_exists}};
                [] ->
                    true = ets:insert(Db, KeydirUser),
                    ok = file:write(Fd, pack(KeydirUser, SharedKey)),
                    ok = file:sync(Fd),
                    {reply, From, ok}
            end;
        {call, From, {read, Nym}} ->
            case ets:lookup(Db, Nym)  of
                [] ->
                    {reply, From, {error, no_such_user}};
                [KeydirUser] ->
                    {reply, From, {ok, KeydirUser#keydir_user{password = <<>>}}}
            end;
        {call, From, {update, #keydir_user{
                                 nym = Nym,
                                 password = Password} = KeydirUser}} ->
            case ets:lookup(Db, Nym) of
                [] ->
                    {reply, From, {error, no_such_user}};
                [#keydir_user{password = Password}] ->
                    true = ets:insert(Db, KeydirUser),
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
                [#keydir_user{password = Password}] ->
                    true = ets:delete(Db, Nym),
                    file:close(Fd),
                    {ok, NewFd} = export_file(Db, DbFilename, SharedKey),
                    {reply, From, ok, State#state{fd = NewFd}};
                [_] ->
                    {reply, From, {error, permission_denied}}
            end;
        {call, From, {list, NymPattern, N}} ->
            {reply, From, {ok, list_users(Db, NymPattern, N, ets:first(Db))}};
        {system, From, Request} ->
            {system, From, Request};
        {'EXIT', Parent, Reason} ->
            file:close(Fd),
            exit(Reason);
        UnknownMessage ->
            ?error_log({unknown_message, UnknownMessage}),
            noreply
    end.

copy_file(DbFilename) ->
    PrePopulatedDbFilename =
        filename:join([code:priv_dir(keydir), <<"keydir.db">>]),
    case filelib:is_regular(PrePopulatedDbFilename) of
        true ->
            case file:copy(PrePopulatedDbFilename, DbFilename) of
                {ok, _BytesCopied} ->
                    ?daemon_log_tag_fmt(
                       system, "Copied Keydir database file from ~s",
                       [PrePopulatedDbFilename]);
                {error, Reason} ->
                    ?daemon_log_tag_fmt(
                       system,
                       "WARNING: Could not copy Keydir database file from ~s: ~s",
                       [DbFilename, inet:format_error(Reason)])
            end,
            ok;
        false ->
            ok
    end.

%% BEWARE: The packing format is interchangble/compatible with the
%% packing format used in local_keydir_serv.erl. That way they can share
%% keydir.db files. Very handy. If you change pack/1 you must do the same
%% in local_keydir_serv.erl.

pack(#keydir_user{nym = Nym,
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
            KeydirUser =
                #keydir_user{nym = Nym,
                             password = Password,
                             email = Email,
                             public_key = elgamal:binary_to_public_key(PublicKey)},
            true = ets:insert(Db, KeydirUser),
            import_file(Fd, Db, SharedKey);
        {error, Reason} ->
            {error, Reason}
    end.

export_file(Db, DbFilename, SharedKey) ->
    _ = file:delete(DbFilename),
    {ok, Fd} = file:open(DbFilename, [read, write, binary]),
    ok = ets:foldl(fun(KeydirUser, ok) ->
                           file:write(Fd, pack(KeydirUser, SharedKey))
                   end, ok, Db),
    ok = file:sync(Fd),
    {ok, Fd}.

list_users(_Db, _NymPattern, 0, _Nym) ->
    [];
list_users(_Db, _NymPattern, _N, '$end_of_table') ->
    [];
list_users(Db, all, N, Nym) ->
    [KeydirUser] = ets:lookup(Db, Nym),
    [KeydirUser|list_users(Db, all, N - 1, ets:next(Db, Nym))];
list_users(Db, {substring, SubStringNym} = NymPattern, N, Nym) ->
    case string:find(Nym, SubStringNym, leading) of
        nomatch ->
            list_users(Db, NymPattern, N, ets:next(Db, Nym));
        _ ->
            [KeydirUser] = ets:lookup(Db, Nym),
            [KeydirUser|list_users(Db, NymPattern, N - 1, ets:next(Db, Nym))]
    end.
