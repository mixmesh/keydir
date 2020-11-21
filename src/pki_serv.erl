-module(pki_serv).
-export([start_link/1, stop/0]).
-export([create/1, read/1, update/1, delete/2, list/2]).
-export([strerror/1]).
-export([message_handler/1]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("apptools/include/serv.hrl").
-include("../include/pki_serv.hrl").

-record(state, {parent :: pid(),
                db :: ets:tid(),
                shared_key :: binary(),
                db_filename :: binary(),
                fd :: file:io_device()}).

%% Exported: start_link

-spec start_link(binary()) ->
          serv:spawn_server_result() |
          {error, {file_error, any()}}.

start_link(GlobalPkiDir) ->
    ?spawn_server_opts(fun(Parent) -> init(Parent, GlobalPkiDir) end,
                       fun ?MODULE:message_handler/1,
                       #serv_options{name = ?MODULE}).

init(Parent, GlobalPkiDir) ->
    DbFilename = filename:join([GlobalPkiDir, <<"pki.db">>]),
    ok = copy_file(DbFilename),
    case file:open(DbFilename, [read, write, binary]) of
        {ok, Fd} ->
            KeyPosition = #pki_user.nym,
            Db = ets:new(pki_db,
                         [ordered_set, {keypos, KeyPosition},
                          public, named_table,
                          {read_concurrency, true}]),
            ObscreteDir = config:lookup([system, 'obscrete-dir']),
            PinFilename = filename:join([ObscreteDir, <<"pin">>]),
            {ok, Pin} = file:read_file(PinFilename),
            PinSalt = config:lookup([system, 'pin-salt']),
            SharedKey = player_crypto:pin_to_shared_key(Pin, PinSalt),
            ok = import_file(Fd, Db, SharedKey),
            ?daemon_log_tag_fmt(
               system, "Global PKI server has been started: ~s",
               [GlobalPkiDir]),
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

-spec create(#pki_user{}) -> ok | {error, user_already_exists}.

create(PkiUser) ->
    serv:call(?MODULE, {create, PkiUser}).

%% Exported: read

-spec read(binary()) -> {ok, #pki_user{}} | {error, no_such_user}.

read(Nym) ->
    case ets:lookup(pki_db, Nym)  of
        [] ->
            {error, no_such_user};
        [PkiUser] ->
            {ok, PkiUser}
    end.

%% Exported: update

-spec update(#pki_user{}) ->
          ok | {error, no_such_user | permission_denied}.

update(PkiUser) ->
    serv:call(?MODULE, {update, PkiUser}).

%% Exported: delete

-spec delete(binary(), binary()) ->
          ok | {error, no_such_user | permission_denied}.

delete(Nym, Password) ->
    serv:call(?MODULE, {delete, Nym, Password}).

%% Exported: list

-spec list({substring, binary()} | all, non_neg_integer()) ->
          {ok, [#pki_user{}]}.

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
    <<"PKI database is corrupt">>;
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
                    {reply, From, {ok, PkiUser#pki_user{password = <<>>}}}
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
        filename:join([code:priv_dir(pki), <<"pki.db">>]),
    case filelib:is_regular(PrePopulatedDbFilename) of
        true ->
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

%% BEWARE: The packing format is interchangble/compatible with the
%% packing format used in local_pki_serv.erl. That way they can share
%% pki.db files. Very handy. If you change pack/1 you must do the same
%% in local_pki_serv.erl.

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

list_users(_Db, _NymPattern, 0, _Nym) ->
    [];
list_users(_Db, _NymPattern, _N, '$end_of_table') ->
    [];
list_users(Db, all, N, Nym) ->
    [PkiUser] = ets:lookup(Db, Nym),
    [PkiUser|list_users(Db, all, N - 1, ets:next(Db, Nym))];
list_users(Db, {substring, SubStringNym} = NymPattern, N, Nym) ->
    case string:find(Nym, SubStringNym, leading) of
        nomatch ->
            list_users(Db, NymPattern, N, ets:next(Db, Nym));
        _ ->
            [PkiUser] = ets:lookup(Db, Nym),
            [PkiUser|list_users(Db, NymPattern, N - 1, ets:next(Db, Nym))]
    end.
