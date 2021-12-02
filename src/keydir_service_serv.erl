-module(keydir_service_serv).
-export([start_link/2]).
-export([export_keydir_db/1]).
-export([message_handler/1]).

-include("../include/keydir_service.hrl").
-include_lib("apptools/include/serv.hrl").
-include_lib("apptools/include/log.hrl").

-record(state, {parent :: pid(),
                keydir_db :: keydir_service:keydir_db(),
                data_dir :: binary(),
                shared_key :: binary()}).

%%
%% Exported: start_link
%%

-spec start_link(keydir_service:keydir_db(), DataDir :: binary()) ->
          serv:spawn_server_result().

start_link(KeydirDb, DataDir) ->
    ?spawn_server(
       fun(Parent) -> init(Parent, KeydirDb, DataDir) end,
       fun ?MODULE:message_handler/1,
       #serv_options{name = ?MODULE}).

init(Parent, KeydirDb, DataDir) ->
    MixmeshDir = config:lookup([system, 'mixmesh-dir']),
    PinFilename = filename:join([MixmeshDir, <<"pin">>]),
    {ok, Pin} = file:read_file(PinFilename),
    PinSalt = config:lookup([system, 'pin-salt']),
    SharedKey = player_crypto:pin_to_shared_key(Pin, PinSalt),
    ?daemon_log_tag_fmt(system, "Keydir server has been started", []),
    {ok, #state{parent = Parent,
                keydir_db = KeydirDb,
                data_dir = DataDir,
                shared_key = SharedKey}}.

%%
%% Exported: export_keydir_db
%%

%% export_keydir_db/1 converts the keydir service database to a
%% keydir.db format suitable for local_keydir_serv.erl. That way
%% Mixmesh can be started with player/keydir-access-settings/mode set
%% to "service" in its configuration and export_keydir_db/1
%% produces a keydir.db file. This file is then to be put in in
%% ${MIXMESH_ROOT}/local-keydir/keydir.db before Mixmesh is restarted
%% with player/keydir-access-settings/mode set to "local".

%% BEWARE: The packing format is interchangble/compatible with the
%% packing performed in local_keydir_serv.erl. If you change pack/1
%% below it *must* be kept in sync with local_keydir_serv.erl.

-spec export_keydir_db(file:filename()) -> ok | {error, file:posix()}.

export_keydir_db(Filename) ->
    serv:call(?MODULE, {export_keydir_db, Filename}).

%%
%% Message handler
%%

message_handler(#state{parent = Parent,
                       keydir_db = {Db, _FileDb},
                       data_dir = DataDir,
                       shared_key = SharedKey}) ->
    receive
        {call, From, {export_keydir_db, Filename}} ->
            _ = file:delete(Filename),
            case file:open(Filename, [write, binary]) of
                {ok, Fd} ->
                    ok = ets:foldl(
                           fun(KeydirKey, ok) ->
                                   file:write(
                                     Fd, pack(DataDir, KeydirKey, SharedKey))
                           end, ok, Db),
                    _ = file:close(Fd),
                    {reply, From, ok};
                {error, Reason} ->
                    {reply, From, {error, Reason}}
            end;
        {system, From, Request} ->
            {system, From, Request};
        {'EXIT', Parent, Reason} ->
            exit(Reason);
        UnknownMessage ->
            ?error_log({unknown_message, UnknownMessage}),
            noreply
    end.

%% BEWARE: The packing format is interchangble/compatible with the
%% packing format used in local_keydir_serv.erl. If you change pack/1
%% you must do the same in local_keydir_serv.erl.

pack(DataDir, #keydir_key{fingerprint = Fingerprint,
                          nym = Nym,
                          password = Password}, SharedKey) ->
    {ok, Pk} = get_pk(DataDir, Fingerprint),
    Nonce = enacl:randombytes(enacl:secretbox_NONCEBYTES()),
    NonceSize = size(Nonce),
    NymSize = size(Nym),
    PasswordSize = size(Password),
    Email = <<"">>, %% We have none available
    EmailSize = size(Email),
    PublicKeyBin = elgamal:pk_to_binary(Pk),
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

get_pk(DataDir, Fingerprint) ->
    EncodedFingerprint = keydir_service:bin_to_hexstr(Fingerprint),
    KeyFilename = filename:join([DataDir, EncodedFingerprint]),
    {ok, ArmoredPgpKey} = file:read_file(KeyFilename),
    {ok, _Opt, PgpKey} = pgp_armor:decode(ArmoredPgpKey),
    keydir_pgp:key_to_pk(PgpKey).
