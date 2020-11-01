-module(local_pki_serv).
-export([start_link/2, stop/1]).
-export([create/2, read/2, update/2, delete/2, list/3]).
-export([import_public_keys/5]).
-export([strerror/1]).
-export([message_handler/1, init/3]).

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

-spec start_link(binary(), binary()) ->
          serv:spawn_server_result() |
          {error, {file_error, any()}} |
          {error, invalid_dir}.

start_link(ObscreteDir, Nym) ->
    ?spawn_server({?MODULE, init, [ObscreteDir, Nym]},
                  {?MODULE, message_handler}).

init(Parent, ObscreteDir, Nym) ->
    DataDir = data_dir(ObscreteDir, Nym),
    case filelib:is_dir(DataDir) of
        true ->
            DbFilename = filename:join([DataDir, <<"pki.db">>]),
            ok = copy_file(DbFilename),
            case file:open(DbFilename, [read, write, binary]) of
                {ok, Fd} ->
                    Db = ets:new(pki_db, [ordered_set, {keypos, #pk.nym}]),
                    [Pin, PinSalt] =
                        config:lookup_children(
                          [pin, 'pin-salt'], config:lookup([system])),
                    SharedKey = player_crypto:pin_to_shared_key(Pin, PinSalt),
                    ok = import_file(Fd, Db, SharedKey),
                    ?daemon_log_tag_fmt(
                       system, "Local PKI server has been started: ~s",
                       [DataDir]),
                    {ok, #state{parent = Parent,
                                db = Db,
                                shared_key = SharedKey,
                                db_filename = DbFilename,
                                fd = Fd}};
                {error, Reason} ->
                    {error, {file_error, Reason}}
            end;
        false ->
            {error, invalid_dir}
    end.

data_dir(ObscreteDir, Nym) ->
    filename:join([ObscreteDir, Nym, <<"player">>, <<"pki">>, <<"data">>]).

%% Exported: stop

-spec stop(serv:name()) -> ok.

stop(PkiServName) ->
    serv:cast(PkiServName, stop).

%% Exported: create

-spec create(serv:name(), #pk{}) -> ok | {error, key_already_exists}.

create(PkiServName, PublicKey) ->
    serv:call(PkiServName, {create, PublicKey}).

%% Exported: read

-spec read(serv:name(), binary()) -> {ok, #pk{}} | {error, no_such_key}.

read(PkiServName, Nym) ->
    serv:call(PkiServName, {read, Nym}).

%% Exported: update

-spec update(serv:name(), #pk{}) ->
          ok | {error, no_such_key | permission_denied}.

update(PkiServName, PublicKey) ->
    serv:call(PkiServName, {update, PublicKey}).

%% Exported: delete

-spec delete(serv:name(), binary()) ->
          ok | {error, no_such_key | permission_denied}.

delete(PkiServName, Nym) ->
    serv:call(PkiServName, {delete, Nym}).

%% Exported: list

-spec list(serv:name(), {substring, binary()} | all,
           non_neg_integer()) ->
          {ok, [#pk{}]}.

list(PkiServName, NymPattern, N) ->
    serv:call(PkiServName, {list, NymPattern, N}).

%% Exported: import_public_keys

import_public_keys(ObscreteDir, Pin, Nym, PinSalt, PublicKeys) ->
    KeyBundleFilename = filename:join([data_dir(ObscreteDir, Nym), "pki.db"]),
    case file:open(KeyBundleFilename, [binary, write]) of
        {ok, Fd} ->
            SharedKey = player_crypto:generate_shared_key(Pin, PinSalt),
            import_public_keys(PublicKeys, Fd, SharedKey);
        {error, Reason} ->
            {error, {file, Reason}}
    end.

import_public_keys([], Fd, _SharedKey) ->
    file:close(Fd);
import_public_keys([PublicKey|Rest], Fd, SharedKey) ->
    case file:write(Fd, pack(PublicKey, SharedKey)) of
        ok ->
            import_public_keys(Rest, Fd, SharedKey);
        {error, Reason} ->
            file:close(Fd),
            {error, Reason}
    end.

%% Exported: strerror

-spec strerror({file_error, any()} |
               invalid_dir |
               key_already_exists |
               no_such_key |
               permission_denied |
               {unknown_error, any()}) -> binary().

strerror({file_error, Reason}) ->
    ?error_log({file_error, Reason}),
    <<"PKI database is corrupt">>;
strerror(invalid_dir) ->
    <<"PKI directory is invalid">>;
strerror(key_already_exists) ->
    <<"Key already exists">>;
strerror(no_such_key) ->
    <<"No such key">>;
strerror(permission_denied) ->
    <<"Permission denied">>;
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
                       [PrePopulatedDbFilename, inet:format_error(Reason)])
            end,
            ok;
        false ->
            ok
    end.

%% BEWARE: The packing format is interchangble/compatible with the
%% packing format used in pki_serv.erl. That way they can share pki.db
%% files. Very handy. If you change pack/1 you must do the same in
%% pki_serv.erl.

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
