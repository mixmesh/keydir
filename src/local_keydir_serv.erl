-module(local_keydir_serv).
-export([start_link/1, stop/1]).
-export([create/2, read/2, update/2, delete/2, list/3, all_nyms/1]).
-export([new_db/4, write_to_db/3]).
-export([strerror/1]).
-export([message_handler/1]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("apptools/include/serv.hrl").
-include_lib("elgamal/include/elgamal.hrl").

-record(state, {parent :: pid(),
                db :: ets:tid(),
                shared_key :: binary(),
                db_filename :: binary(),
                fd :: file:io_device()}).

%% Exported: start_link

-spec start_link(binary()) ->
          serv:spawn_server_result() |
          {error, {file_error, any()}}.

start_link(LocalKeydirDir) ->
    ?spawn_server(fun(Parent) -> init(Parent, LocalKeydirDir) end,
                  fun ?MODULE:message_handler/1).

init(Parent, LocalKeydirDir) ->
    DbFilename = filename:join([LocalKeydirDir, <<"keydir.db">>]),
    ok = copy_file(DbFilename),
    case file:open(DbFilename, [read, write, binary]) of
        {ok, Fd} ->
            Db = ets:new(keydir_db, [ordered_set, {keypos, #pk.nym}]),
            MixmeshDir = config:lookup([system, 'mixmesh-dir']),
            PinFilename = filename:join([MixmeshDir, <<"pin">>]),
            {ok, Pin} = file:read_file(PinFilename),
            PinSalt = config:lookup([system, 'pin-salt']),
            SharedKey = player_crypto:pin_to_shared_key(Pin, PinSalt),
            ok = import_file(Fd, Db, SharedKey),
            ?daemon_log_tag_fmt(
               system, "Local Keydir server has been started: ~s",
               [LocalKeydirDir]),
            {ok, #state{parent = Parent,
                        db = Db,
                        shared_key = SharedKey,
                        db_filename = DbFilename,
                        fd = Fd}};
        {error, Reason} ->
            {error, {file_error, Reason}}
    end.

%% Exported: stop

-spec stop(serv:name()) -> ok.

stop(KeydirServName) ->
    serv:cast(KeydirServName, stop).

%% Exported: create

-spec create(serv:name(), #pk{}) -> ok | {error, key_already_exists}.

create(KeydirServName, PublicKey) ->
    serv:call(KeydirServName, {create, PublicKey}).

%% Exported: read

-spec read(serv:name(), binary()) -> {ok, #pk{}} | {error, no_such_key}.

read(KeydirServName, Nym) ->
    serv:call(KeydirServName, {read, Nym}).

%% Exported: update

-spec update(serv:name(), #pk{}) ->
          ok | {error, no_such_key}.

update(KeydirServName, PublicKey) ->
    serv:call(KeydirServName, {update, PublicKey}).

%% Exported: delete

-spec delete(serv:name(), binary()) ->
          ok | {error, no_such_key}.

delete(KeydirServName, Nym) ->
    serv:call(KeydirServName, {delete, Nym}).

%% Exported: list

-spec list(serv:name(), {substring, binary()} | all,
           non_neg_integer()) ->
          {ok, [#pk{}]}.

list(KeydirServName, NymPattern, N) ->
    serv:call(KeydirServName, {list, NymPattern, N}).

%% Exported: all_nyms

-spec all_nyms(serv:name()) -> {ok, [binary()]}.

all_nyms(KeydirServName) ->
    serv:call(KeydirServName, all_nyms).

%% Exported: new_db

new_db(Nym, MixmeshDir, Pin, PinSalt) ->
    LocalKeydirDir =
        filename:join([MixmeshDir, Nym, <<"player">>, <<"local-keydir">>]),
    DbFilename =
        filename:join([LocalKeydirDir, <<"keydir.db">>]),
    file:delete(DbFilename),
    case file:open(DbFilename, [binary, write]) of
        {ok, File} ->
            SharedKey = player_crypto:generate_shared_key(Pin, PinSalt),
            {ok, File, SharedKey};
        {error, Reason} ->
            {error, {file, Reason, DbFilename}}
    end.

%% Exported: new_db

write_to_db(File, SharedKey, PublicKey) ->
    ok = file:write(File, pack(PublicKey, SharedKey)).

%% Exported: strerror

-spec strerror({file_error, any()} |
               key_already_exists |
               no_such_key |
               {unknown_error, any()}) -> binary().

strerror({file_error, Reason}) ->
    ?error_log({file_error, Reason}),
    <<"Keydir database is corrupt">>;
strerror(key_already_exists) ->
    <<"Key already exists">>;
strerror(no_such_key) ->
    <<"No such key">>;
strerror({file, Reason}) ->
    ?l2b(file:format_error(Reason));
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
        {call, From, {create, PublicKey}} ->
            case ets:lookup(Db, PublicKey#pk.nym) of
                [_] ->
                    {reply, From, {error, key_already_exists}};
                [] ->
                    true = ets:insert(Db, PublicKey),
                    ok = file:write(Fd, pack(PublicKey, SharedKey)),
                    ok = file:sync(Fd),
                    {reply, From, ok}
            end;
        {call, From, {read, Nym}} ->
            case ets:lookup(Db, Nym)  of
                [] ->
                    {reply, From, {error, no_such_key}};
                [PublicKey] ->
                    {reply, From, {ok, PublicKey}}
            end;
        {call, From, {update, #pk{nym = Nym} = PublicKey}} ->
            case ets:lookup(Db, Nym) of
                [] ->
                    {reply, From, {error, no_such_key}};
                [_] ->
                    true = ets:insert(Db, PublicKey),
                    file:close(Fd),
                    {ok, NewFd} = export_file(Db, DbFilename, SharedKey),
                    {reply, From, ok, State#state{fd = NewFd}}
            end;
        {call, From, {delete, Nym}} ->
            case ets:lookup(Db, Nym) of
                [] ->
                    {reply, From, {error, no_such_key}};
                [_] ->
                    true = ets:delete(Db, Nym),
                    file:close(Fd),
                    {ok, NewFd} = export_file(Db, DbFilename, SharedKey),
                    {reply, From, ok, State#state{fd = NewFd}}
            end;
        {call, From, {list, NymPattern, N}} ->
            {reply, From, {ok, list_keys(Db, NymPattern, N, ets:first(Db))}};
        {call, From, all_nyms} ->
            Nyms = ets:foldl(fun(#pk{nym = Nym}, Acc) -> [Nym|Acc] end, [], Db),
            {reply, From, {ok, Nyms}};
        {neighbour_workers, _NeighbourWorkers} ->
            noreply;
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
    %% note must have a default of false, simulator may not always be present!
    case config:lookup([simulator, enabled], false) of
        true ->
            PrePopulatedDbFilename =
                filename:join([code:priv_dir(simulator),
                               config:lookup([simulator, 'data-set']),
                               <<"keydir.db">>]),
            case file:copy(PrePopulatedDbFilename, DbFilename) of
                {ok, _BytesCopied} ->
                    ?daemon_log_tag_fmt(
                       system, "Copied Keydir database file from ~s",
                       [PrePopulatedDbFilename]);
                {error, Reason} ->
                    ?daemon_log_tag_fmt(
                       system,
                       "WARNING: Could not copy Keydir database file from ~s: ~s",
                       [PrePopulatedDbFilename, inet:format_error(Reason)])
            end,
            ok;
        false ->
            ok
    end.

%% BEWARE: The packing format is interchangble/compatible with the
%% packing format used in keydir_serv.erl. That way they can share keydir.db
%% files. Very handy. If you change pack/1 you must do the same in
%% keydir_serv.erl.

pack(#pk{nym = Nym} = PublicKey, SharedKey) ->
    Nonce = enacl:randombytes(enacl:secretbox_NONCEBYTES()),
    NonceSize = size(Nonce),
    NymSize = size(Nym),
    Password = <<>>,
    PasswordSize = size(Password),
    Email = <<>>,
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
                   _Nym:NymSize/binary,
                   PasswordSize:16/unsigned-integer,
                   _Password:PasswordSize/binary,
                   EmailSize:16/unsigned-integer,
                   _Email:EmailSize/binary,
                   PublicKeySize:16/unsigned-integer,
                   PublicKeyBin:PublicKeySize/binary>>} =
                enacl:secretbox_open(EncryptedEntry, Nonce, SharedKey),
            PublicKey = elgamal:binary_to_public_key(PublicKeyBin),
            true = ets:insert(Db, PublicKey),
            import_file(Fd, Db, SharedKey);
        {error, Reason} ->
            {error, Reason}
    end.

export_file(Db, DbFilename, SharedKey) ->
    _ = file:delete(DbFilename),
    {ok, Fd} = file:open(DbFilename, [read, write, binary]),
    ok = ets:foldl(fun(PublicKey, ok) ->
                           file:write(Fd, pack(PublicKey, SharedKey))
                   end, ok, Db),
    ok = file:sync(Fd),
    {ok, Fd}.

list_keys(_Db, _NymPattern, 0, _Nym) ->
    [];
list_keys(_Db, _NymPattern, _N, '$end_of_table') ->
    [];
list_keys(Db, all, N, Nym) ->
    [PublicKey] = ets:lookup(Db, Nym),
    [PublicKey|list_keys(Db, all, N - 1, ets:next(Db, Nym))];
list_keys(Db, {substring, SubStringNym} = NymPattern, N, Nym) ->
    case string:find(Nym, SubStringNym, leading) of
        nomatch ->
            list_keys(Db, NymPattern, N, ets:next(Db, Nym));
        _ ->
            [PublicKey] = ets:lookup(Db, Nym),
            [PublicKey|list_keys(Db, NymPattern, N - 1, ets:next(Db, Nym))]
    end.
