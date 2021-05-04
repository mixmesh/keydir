-module(keydir_service).
-export([start_link/4, bin_to_hexstr/1]).
-export([handle_http_request/4]).
-export([purge_sessions/1]).
-export_type([key_id/0, user_id/0, nym/0, password/0]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("rester/include/rester_http.hrl").
-include("../include/keydir_service.hrl").

-define(SESSION_TICKET_SIZE, 32).
-define(VALID_UNTIL_TIME, (60 * 5)). % 5 minutes
-define(SESSION_PURGE_TIME, 15000). % 15 seconds

-type key_id() :: binary().
-type fingerprint() :: binary().
-type user_id() :: binary().
-type nym() :: binary().
-type password() :: binary().

-record(session,
        {session_ticket :: binary() | undefined,
         type :: {password, password()} |
                 {bank_id,
                  {pending, bank_id:order_ref(), bank_id:hint_code()}} |
                 {bank_id, {failed, bank_id:hint_code()}} |
                 {bank_id,
                  {complete, bank_id:given_name(), bank_id:personal_number()}} |
                 undefined,
         key_id :: key_id() | undefined,
         valid_until :: pos_integer() | '$1'}).

%%
%% Exported: start_link
%%

start_link(Address, Port, CertFilename, DataDir) ->
    SessionDb = new_session_db(),
    KeydirDb = new_keydir_db(DataDir),
    {ok, _TRef} =
        timer:apply_interval(?SESSION_PURGE_TIME, ?MODULE, purge_sessions,
                             [SessionDb]),
    ResterHttpArgs =
	[{request_handler,
          {?MODULE, handle_http_request, [DataDir, SessionDb, KeydirDb]}},
	 {verify, verify_none},
	 {ifaddr, Address},
	 {certfile, CertFilename},
	 {nodelay, true},
	 {reuseaddr, true}],
    ?daemon_log_tag_fmt(system, "Keydir service started on ~s:~w",
                        [inet:ntoa(Address), Port]),
    rester_http_server:start_link(Port, ResterHttpArgs).

%%
%% Exported: handle_http_request
%%

handle_http_request(Socket, Request, Body, XArgs) ->
    ?dbg_log({handle_http_request,
              rester_http:format_request(Request),
              rester_http:format_hdr(Request#http_request.headers),
              Body}),
    try
        case Request#http_request.method of
            'GET' ->
                handle_http_response(
                  Socket, Request,
                  handle_http_get(Socket, Request, Body, tl(XArgs)));
            'POST' ->
                handle_http_response(
                  Socket, Request,
                  handle_http_post(Socket, Request, Body, tl(XArgs)));
            _ ->
                response(Socket, Request, 405, default_phrase(405))
        end
    catch
        _Class:Reason:StackTrace ->
	    ?error_log({handle_http_request, Reason, StackTrace}),
	    erlang:error(Reason)
    end.

handle_http_get(_Socket, #http_request{uri = Url}, _Body,
                [DataDir, _SessionDb, KeydirDb]) ->
    case string:tokens(Url#url.path, "/") of
        %% The OpenPGP HTTP Keyserver Protocol (HKP)
        %% draft-shaw-openpgp-hkp-00.txt
        ["pks", "lookup"] ->
            ParsedQueryString = uri_string:dissect_query(Url#url.querypart),
            case lists:keysearch("op", 1, ParsedQueryString) of
                {value, {_, "get"}} ->
                    case lists:keysearch("search", 1, ParsedQueryString) of
                        {value, {_, "0x" ++ KeyIdHexString}} ->
                            KeyId = hexstr_to_bin(KeyIdHexString),
                            case keydir_read(KeydirDb, {key_id, KeyId}) of
                                [_] ->
                                    EncodedKeyId = base64:encode(KeyId),
                                    KeyFilename =
                                        filename:join([DataDir, EncodedKeyId]),
                                    {200, {file, KeyFilename},
                                     [{content_type,
                                       "application/octet-stream"}]};
                                [] ->
                                    {json, 404,
                                     #{<<"errorMessage">> => <<"No such key">>}}
                            end;
                        {value, _} ->
                            501;
                        false ->
                            404
                    end;
                {value, {_, Op}} when Op == "index" orelse Op == "vindex" ->
                    case lists:keysearch("search", 1, ParsedQueryString) of
                        {value, {_, "0x" ++ KeyIdHexString}} ->
                            KeyId = hexstr_to_bin(KeyIdHexString),
                            Keys = keydir_read(KeydirDb, {key_id, KeyId}),
                            {json, 200, #{<<"keys">> => matching_keys(Keys)}};
                        {value, {_, Text}} ->
                            Keys = keydir_read(KeydirDb, #{nym => ?l2b(Text)}),
                            {json, 200, #{<<"keys">> => matching_keys(Keys)}};
                        false ->
                            404
                    end;
                {value, _} ->
                    501;
                false ->
                    400
            end;
        _Tokens ->
            501
    end.

handle_http_post(Socket, Request, Body, [DataDir, SessionDb, KeydirDb]) ->
    Url = Request#http_request.uri,
    case string:tokens(Url#url.path, "/") of
        ["passwordLogin"] ->
            try
                JsonValue = parse_json_body(Request, Body),
                [EncodedKeyId, Password] =
                    rest_util:parse_json_params(
                      JsonValue,
                      [{<<"keyId">>, fun erlang:is_binary/1},
                       {<<"password">>, fun erlang:is_binary/1}]),
                KeyId = base64:decode(EncodedKeyId),
                case keydir_read(KeydirDb, {key_id, KeyId}) of
                    [] ->
                        start_password_session(SessionDb, KeyId, Password);
                    [#keydir_key{password = Password}] ->
                        start_password_session(SessionDb, KeyId, Password);
                    [_] ->
                        {json, 403, #{<<"errorMessage">> =>
                                          <<"Invalid keyId or password">>}}
                end
            catch
                throw:{error, ErrorMessage} ->
                    {json, 400, #{<<"errorMessage">> => ErrorMessage}};
                throw:{response, Response} ->
                    Response
            end;
        ["bankIdAuth"] ->
            try
                JsonValue = parse_json_body(Request, Body),
                [EncodedKeyId, PersonalNumber] =
                    rest_util:parse_json_params(
                      JsonValue,
                      [{<<"keyId">>, fun erlang:is_binary/1},
                       {<<"personalNumber">>, fun erlang:is_binary/1}]),
                KeyId = base64:decode(EncodedKeyId),
                case keydir_read(KeydirDb, {key_id, KeyId}) of
                    [] ->
                        start_bank_id_session(
                          Socket, SessionDb, KeyId, PersonalNumber);
                    [#keydir_key{personal_number = PersonalNumber}] ->
                        start_bank_id_session(
                          Socket, SessionDb, KeyId, PersonalNumber);
                    [_] ->
                        {json, 403,
                         #{<<"errorMessage">> =>
                               <<"Invalid keyId or personalNumber">>}}
                end
            catch
                throw:{error, ErrorMessage} ->
                    {json, 400, #{<<"errorMessage">> => ErrorMessage}};
                throw:{response, Response} ->
                    Response
            end;
        ["bankIdCollect"] ->
            try
                JsonValue = parse_json_body(Request, Body),
                [EncodedSessionTicket] =
                    rest_util:parse_json_params(
                      JsonValue,
                      [{<<"sessionTicket">>, fun erlang:is_binary/1}]),
                SessionTicket = base64:decode(EncodedSessionTicket),
                case session_lookup(SessionDb, SessionTicket) of
                    [#session{
                        type = {bank_id, {pending, OrderRef, _HintCode}}} =
                         Session] ->
                        case bank_id:collect(OrderRef) of
                            {pending, HintCode} ->
                                true =
                                    session_insert(
                                      SessionDb,
                                      Session#session{
                                        type =
                                            {bank_id,
                                             {pending, OrderRef, HintCode}}}),
                                {json, 200,
                                 #{<<"status">> => <<"pending">>,
                                   <<"hintCode">> => HintCode}};
                            {failed, HintCode} ->
                                true =
                                    session_insert(
                                      SessionDb,
                                      Session#session{
                                        type = {bank_id, {failed, HintCode}}}),
                                {json, 200,
                                 #{<<"status">> => <<"failed">>,
                                   <<"hintCode">> => HintCode}};
                            {complete, GivenName, PersonalNumber} ->
                                true =
                                    session_insert(
                                      SessionDb,
                                      Session#session{
                                        type =
                                            {bank_id,
                                             {complete, GivenName,
                                              PersonalNumber}}}),
                                {json, 200, #{<<"status">> => <<"complete">>}};
                            {bad_response, Status, Phrase, ResponseJsonValue} ->
                                ?error_log({bad_bank_id_response, Status,
                                            Phrase, ResponseJsonValue}),
                                500;
                            {http_error, Reason} ->
                                ?error_log({http_error, Reason}),
                                500
                        end;
                    [] ->
                        ?dbg_log({missing_session_ticket, SessionTicket}),
                        {json, 403,
                         #{<<"errorMessage">> => <<"No active session">>}};
                    [Session] ->
                        ?dbg_log({session_ticket_mismatch, Session}),
                        {json, 403,
                         #{<<"errorMessage">> => <<"Session mismatch">>}}
                end
            catch
                throw:{error, ErrorMessage} ->
                    {json, 400, #{<<"errorMessage">> => ErrorMessage}};
                throw:{response, Response} ->
                    Response
            end;
        ["bankIdCancel"] ->
            try
                JsonValue = parse_json_body(Request, Body),
                [EncodedSessionTicket] =
                    rest_util:parse_json_params(
                      JsonValue,
                      [{<<"sessionTicket">>, fun erlang:is_binary/1}]),
                SessionTicket = base64:decode(EncodedSessionTicket),
                case session_lookup(SessionDb, SessionTicket) of
                    [#session{type = {bank_id,
                                      {pending, OrderRef, _HintCode}}}] ->
                        case bank_id:cancel(OrderRef) of
                            ok ->
                                200;
                            {bad_response, Status, Phrase, ResponseJsonValue} ->
                                ?error_log({bad_response, Status, Phrase,
                                            ResponseJsonValue}),
                                500;
                            {http_error, Reason} ->
                                ?error_log({http_error, Reason}),
                                500
                        end;
                    [] ->
                        ?dbg_log({missing_session_ticket, SessionTicket}),
                        {json, 403,
                         #{<<"errorMessage">> => <<"No active session">>}};
                    [Session] ->
                        ?dbg_log({session_ticket_mismatch, Session}),
                        {json, 403,
                         #{<<"errorMessage">> => <<"Session mismatch">>}}
                end
            catch
                throw:{error, ErrorMessage} ->
                    {json, 400, #{<<"errorMessage">> => ErrorMessage}};
                throw:{response, Response} ->
                    Response
            end;
        ["logout"] ->
            try
                JsonValue = parse_json_body(Request, Body),
                [EncodedSessionTicket] =
                    rest_util:parse_json_params(
                      JsonValue,
                      [{<<"sessionTicket">>, fun erlang:is_binary/1}]),
                SessionTicket = base64:decode(EncodedSessionTicket),
                case session_lookup(SessionDb, SessionTicket) of
                    [_] ->
                        true = session_delete(SessionDb, SessionTicket),
                        200;
                    [] ->
                        ?dbg_log({missing_session_ticket, SessionTicket}),
                        {json, 403,
                         #{<<"errorMessage">> => <<"No such session">>}}
                end
            catch
                throw:{error, ErrorMessage} ->
                    {json, 400, #{<<"errorMessage">> => ErrorMessage}};
                throw:{response, Response} ->
                    Response
            end;
        ["create"] ->
            try
                JsonValue = parse_json_body(Request, Body),
                [EncodedSessionTicket, EncodedKey] =
                    rest_util:parse_json_params(
                      JsonValue,
                      [{<<"sessionTicket">>, fun erlang:is_binary/1},
                       {<<"key">>,  fun erlang:is_binary/1}]),
                SessionTicket = base64:decode(EncodedSessionTicket),
                case session_lookup(SessionDb, SessionTicket) of
                    [#session{type = {password, _Password}} = Session] ->
                        create_key(DataDir, SessionDb, KeydirDb, EncodedKey,
                                   Session);
                    [#session{
                        type = {bank_id,
                                {complete, _GivenName, _PersonalNumber}}} =
                         Session] ->
                        create_key(DataDir, SessionDb, KeydirDb, EncodedKey,
                                   Session);
                    [] ->
                        ?dbg_log({missing_session_ticket, SessionTicket}),
                        {json, 403,
                         #{<<"errorMessage">> => <<"No active session">>}};
                    [Session] ->
                        ?dbg_log({session_ticket_mismatch, Session}),
                        {json, 403,
                         #{<<"errorMessage">> => <<"Session mismatch">>}}
                end
            catch
                throw:{error, ErrorMessage} ->
                    {json, 400, #{<<"errorMessage">> => ErrorMessage}};
                throw:{response, Response} ->
                    Response
            end;
        ["read"] ->
            try
                JsonValue = parse_json_body(Request, Body),
                [EncodedKeyId, EncodedFingerprint, UserId, Nym, GivenName,
                 PersonalNumber, Verified] =
                    rest_util:parse_json_params(
                      JsonValue,
                      [{<<"keyId">>, fun erlang:is_binary/1, undefined},
                       {<<"fingerprint">>, fun erlang:is_binary/1, undefined},
                       {<<"userId">>, fun erlang:is_binary/1, undefined},
                       {<<"nym">>, fun erlang:is_binary/1, undefined},
                       {<<"givenName">>, fun erlang:is_binary/1, undefined},
                       {<<"personalNumber">>, fun erlang:is_binary/1,
                        undefined},
                       {<<"verified">>, fun erlang:is_boolean/1, undefined}]),
                KeyId = conditional_base64_decode(EncodedKeyId),
                Fingerprint = conditional_base64_decode(EncodedFingerprint),
                case keydir_read(KeydirDb,
                                 #{key_id => KeyId,
                                   fingerprint => Fingerprint,
                                   user_id => UserId,
                                   nym => Nym,
                                   given_name => GivenName,
                                   personal_number => PersonalNumber,
                                   verified => Verified}) of
                    [] ->
                        {json, 404, #{<<"errorMessage">> => <<"No such key">>}};
                    [#keydir_key{key_id = KeyId}] ->
                        KeyFilename = filename:join([DataDir, EncodedKeyId]),
                        {200, {file, KeyFilename},
                         [{content_type, "application/octet-stream"}]};
                    Keys ->
                        {json, 200, #{<<"keys">> => matching_keys(Keys)}}
                end
            catch
                throw:{error, ErrorMessage} ->
                    {json, 400, #{<<"errorMessage">> => ErrorMessage}};
                throw:{response, Response} ->
                    Response
            end;
        ["update"] ->
            try
                JsonValue = parse_json_body(Request, Body),
                [SessionTicket, EncodedKey] =
                    rest_util:parse_json_params(
                      JsonValue,
                      [{<<"sessionTicket">>, fun erlang:is_binary/1},
                       {<<"key">>,  fun erlang:is_binary/1}]),
                case session_lookup(SessionDb, SessionTicket) of
                    [#session{type = {password, _Password}} = Session] ->
                        update_key(DataDir, SessionDb, KeydirDb, EncodedKey,
                                   Session);
                    [#session{
                        type = {bank_id,
                                {complete, _GivenName, _PersonalNumber}}} =
                         Session] ->
                        update_key(DataDir, SessionDb, KeydirDb, EncodedKey,
                                   Session);
                    [] ->
                        ?dbg_log({missing_session_ticket, SessionTicket}),
                        {json, 403,
                         #{<<"errorMessage">> => <<"No active session">>}};
                    [Session] ->
                        ?dbg_log({session_ticket_mismatch, Session}),
                        {json, 403,
                         #{<<"errorMessage">> => <<"Session mismatch">>}}
                end
            catch
                throw:{error, ErrorMessage} ->
                    {json, 400, #{<<"errorMessage">> => ErrorMessage}};
                throw:{response, Response} ->
                    Response
            end;
        ["delete"] ->
            try
                JsonValue = parse_json_body(Request, Body),
                [EncodedSessionTicket, EncodedKeyId] =
                    rest_util:parse_json_params(
                      JsonValue,
                      [{<<"sessionTicket">>, fun erlang:is_binary/1},
                       {<<"keyId">>,  fun erlang:is_binary/1}]),
                SessionTicket = base64:decode(EncodedSessionTicket),
                KeyId = base64:decode(EncodedKeyId),
                case session_lookup(SessionDb, SessionTicket) of
                    [#session{key_id = KeyId}] ->
                        ok = keydir_delete(KeydirDb, KeyId),
                        KeyFilename = filename:join([DataDir, EncodedKeyId]),
                        ok = file:delete(KeyFilename),
                        200;
                    [] ->
                        ?dbg_log({missing_session_ticket, SessionTicket}),
                        {json, 403,
                         #{<<"errorMessage">> => <<"No active session">>}};
                    [Session] ->
                        ?dbg_log({session_ticket_mismatch, Session}),
                        {json, 403,
                         #{<<"errorMessage">> => <<"Session mismatch">>}}
                end
            catch
                throw:{error, ErrorMessage} ->
                    {json, 400, #{<<"errorMessage">> => ErrorMessage}};
                throw:{response, Response} ->
                    Response
            end;
        %% The OpenPGP HTTP Keyserver Protocol (HKP)
        %% draft-shaw-openpgp-hkp-00.txt
        ["pks", "add"] ->
            create_hkp_key(DataDir, KeydirDb, Body);
        _Tokens ->
            501
    end.

%%
%% Request: /login
%%

start_password_session(SessionDb, KeyId, Password) ->
    SessionTicket = enacl:randombytes(?SESSION_TICKET_SIZE),
    Now = erlang:system_time(seconds),
    Session =
        #session{
           session_ticket = SessionTicket,
           type = {password, Password},
           key_id = KeyId,
           valid_until = Now + ?VALID_UNTIL_TIME},
    true = session_insert(SessionDb, Session),
    {json, 200, #{<<"sessionTicket">> => base64:encode(SessionTicket)}}.

%%
%% Request: /bankIdAuth
%%

start_bank_id_session(Socket, SessionDb, KeyId, PersonalNumber) ->
    ClientIpAddress = client_ip_address(Socket),
    case bank_id:auth(PersonalNumber, ClientIpAddress) of
        {ok, OrderRef} ->
            SessionTicket = enacl:randombytes(?SESSION_TICKET_SIZE),
            Now = erlang:system_time(seconds),
            Session =
                #session{
                   session_ticket = SessionTicket,
                   type = {bank_id, {pending, OrderRef, <<"auth">>}},
                   key_id = KeyId,
                   valid_until = Now + ?VALID_UNTIL_TIME},
            true = session_insert(SessionDb, Session),
            {json, 200, #{<<"sessionTicket">> => base64:encode(SessionTicket)}};
        {bad_response, Status, Phrase, ResponseJsonValue} ->
            ?error_log({bad_response, Status, Phrase, ResponseJsonValue}),
            500;
        {http_error, Reason} ->
            ?error_log({http_error, Reason}),
            500
    end.

%%
%% Request: /create
%%

create_key(DataDir, SessionDb, KeydirDb, EncodedKey, Session) ->
    insert_key(DataDir, SessionDb, KeydirDb, EncodedKey, Session, create).

insert_key(DataDir, SessionDb, KeydirDb, EncodedKey,
           #session{type = SessionType, key_id = SessionKeyId} = Session,
           Mode) ->
    case keydir_pgp:decode_key(EncodedKey) of
        {ok, #{<<"keyId">> := EncodedKeyId,
               <<"fingerprint">> := EncodedFingerprint,
               <<"userIds">> := UserIds,
               <<"userAttributes">> := UserAttributes}} ->
            KeyId = base64:decode(EncodedKeyId),
            Fingerprint = base64:decode(EncodedFingerprint),
            ActualKeyId = extract_key_id(SessionKeyId, KeyId),
            ActualNym = extract_nym(UserIds, UserAttributes),            
            case SessionType of
                {password, Password} ->
                    case keydir_pgp:user_attribute_values(
                           [?GIVEN_NAME_ATTRIBUTE,
                            ?PERSONAL_NUMBER_ATTRIBUTE], UserAttributes) of
                        [undefined, undefined] ->
                            Key =
                                #keydir_key{
                                   key_id = ActualKeyId,
                                   fingerprint = Fingerprint,
                                   user_ids = UserIds,
                                   nym = ActualNym, 
                                   password = Password,
                                   verified = false},
                            store_key(
                              DataDir, SessionDb, KeydirDb, Session, Mode,
                              EncodedKey, Key);
                        [_, _] ->
                            {json, 400,
                             #{<<"errorMessage">> =>
                                   <<"User Attributes of type GIVEN-NAME/129 and PERSONAL-NUMBER/130 must *not* be specified">>}}
                    end;
                {bank_id, {complete, GivenName, PersonalNumber}} ->
                    case keydir_pgp:user_attribute_values(
                           [?GIVEN_NAME_ATTRIBUTE,
                            ?PERSONAL_NUMBER_ATTRIBUTE], UserAttributes) of
                        [_GivenName, undefined] ->
                            {json, 400,
                             #{<<"errorMessage">> =>
                                   "A User Attribute of type PERSONAL-NUMBER/130 *must* be specified"}};
                        [undefined, PersonalNumber] ->
                            Key =
                                #keydir_key{
                                   key_id = ActualKeyId,
                                   fingerprint = Fingerprint,
                                   user_ids = UserIds,
                                   nym = ActualNym, 
                                   given_name = undefined,
                                   personal_number = PersonalNumber,
                                   verified = true},
                            store_key(
                              DataDir, SessionDb, KeydirDb, Session, Mode,
                              EncodedKey, Key);
                        [GivenName, PersonalNumber] ->
                            Key =
                                #keydir_key{
                                   key_id = ActualKeyId,
                                   fingerprint = Fingerprint,
                                   user_ids = UserIds,
                                   nym = ActualNym, 
                                   given_name = GivenName,
                                   personal_number = PersonalNumber,
                                   verified = true},
                            store_key(
                              DataDir, SessionDb, KeydirDb, Session, Mode,
                              EncodedKey, Key);
                        [GivenName, _MismatchedPersonalNumber] ->
                            {json, 400,
                             #{<<"errorMessage">> =>
                                   "The User Attribute of type PERSONAL-NUMBER/130 does not match login credentials"}};
                        [_MismatchedGivenName, PersonalNumber] ->
                            {json, 400,
                             #{<<"errorMessage">> =>
                                   "The User Attribute of type GIVEN-NAME/129 does not match login credentials"}}
                    end
            end;
        {error, Reason} ->
	    ?error_log({invalid_key, EncodedKey, Reason}),
            {json, 400, #{<<"errorMessage">> => <<"Invalid key">>}}
    end.

extract_key_id(undefined, KeyId) ->
    KeyId;
extract_key_id(KeyId, KeyId) ->
    KeyId;
extract_key_id(_SessionKeyId, _KeyId) ->
    throw({response, {json, 401,
                      #{<<"errorMessage">> =>
                            <<"Key ID does not match login credentials">>}}}).

extract_nym(UserIds, UserAttributes) ->
    case UserIds of
        [] ->
            case keydir_pgp:user_attribute_values(
                   [?NYM_ATTRIBUTE], UserAttributes) of
                [NymAttribute] ->
                    NymAttribute;
                [] ->
                    throw(
                      {response,
                       {json, 400,
                        #{<<"errorMessage">> =>
                              "A User ID or a User Attribute of type NYM/128 *must* be specified"}}})
            end;
        [UserId|_] ->
            UserId
    end.

store_key(DataDir, SessionDb, KeydirDb, Session, create, EncodedKey,
          #keydir_key{key_id = KeyId} = Key) ->
    case keydir_create(KeydirDb, Key) of
        ok when Session == undefined ->
            ok = write_key(DataDir, EncodedKey, KeyId),
            200;
        ok ->
            true = session_insert(SessionDb, Session#session{key_id = KeyId}),
            ok = write_key(DataDir, EncodedKey, KeyId),
            200;
        {error, already_exists} ->
            {json, 303, #{<<"errorMessage">> => <<"Key already exists">>}}
    end;
store_key(DataDir, SessionDb, KeydirDb, Session, update, EncodedKey,
          #keydir_key{key_id = KeyId} = Key) ->
    ok = keydir_update(KeydirDb, Key),
    true = session_insert(SessionDb, Session#session{key_id = KeyId}),
    ok = write_key(DataDir, EncodedKey, KeyId),
    200.

write_key(DataDir, EncodedKey, KeyId) ->
    EncodedKeyId = base64:encode(KeyId),
    KeyFilename = filename:join([DataDir, EncodedKeyId]),
    file:write_file(KeyFilename, EncodedKey).

%%
%% Request: /read
%%

matching_keys([]) ->
    [];
matching_keys([Key|Rest]) ->
    [set_if_defined(
       #{<<"keyId">> => base64:encode(Key#keydir_key.key_id),
         <<"fingerprint">> => base64:encode(Key#keydir_key.fingerprint),
         <<"userIds">> => Key#keydir_key.user_ids,
         <<"nym">> => Key#keydir_key.nym,
         <<"verified">> => Key#keydir_key.verified},
       [{<<"givenName">>, Key#keydir_key.given_name},
        {<<"personalNumber">>, Key#keydir_key.personal_number}])|
     matching_keys(Rest)].

set_if_defined(Map, []) ->
    Map;
set_if_defined(Map, [{_KeyName, undefined}|Rest]) ->
    set_if_defined(Map, Rest);
set_if_defined(Map, [{KeyName, Value}|Rest]) ->
    set_if_defined(Map#{KeyName => Value}, Rest).

%%
%% Request: /update
%%

update_key(DataDir, SessionDb, KeydirDb, EncodedKey, Session) ->
    insert_key(DataDir, SessionDb, KeydirDb, EncodedKey, Session, update).


%%
%% Request: /add
%%

create_hkp_key(DataDir, KeydirDb, EncodedKey) ->
    case keydir_pgp:decode_key(EncodedKey) of
        {ok, #{<<"keyId">> := EncodedKeyId,
               <<"fingerprint">> := Fingerprint,
               <<"userIds">> := UserIds,
               <<"userAttributes">> := UserAttributes}} ->
            KeyId = base64:decode(EncodedKeyId),
            ActualNym = extract_nym(UserIds, UserAttributes),
            case keydir_pgp:user_attribute_values(
                   [?GIVEN_NAME_ATTRIBUTE,
                    ?PERSONAL_NUMBER_ATTRIBUTE], UserAttributes) of
                [undefined, undefined] ->
                    Key =
                        #keydir_key{
                           key_id = KeyId,
                           fingerprint = Fingerprint,
                           user_ids = UserIds,
                           nym = ActualNym, 
                           verified = false},
                    store_key(
                      DataDir, undefined, KeydirDb, undefined, create,
                      EncodedKey, Key);
                [_, _] ->
                    {json, 400,
                     #{<<"errorMessage">> =>
                           <<"User Attributes of type GIVEN-NAME/129 and PERSONAL-NUMBER/130 must *not* be specified">>}}
            end;
        {error, Reason} ->
	    ?error_log({invalid_key, EncodedKey, Reason}),
            {json, 400, #{<<"errorMessage">> => <<"Invalid key">>}}
    end.
%%
%% Exported: bin_to_hexstr
%%

bin_to_hexstr(Bin) ->
    lists:flatten([io_lib:format("~2.16.0B", [X]) || X <- binary_to_list(Bin)]).

%%
%% Session database primitives
%%

new_session_db() ->
    ets:new(?MODULE, [public, {keypos, #session.session_ticket}]).

session_insert(SessionDb, Session) ->
    ets:insert(SessionDb, Session).

session_lookup(SessionDb, SessionTicket) ->
    ets:lookup(SessionDb, SessionTicket).

session_delete(SessionDb, SessionTicket) ->
    ets:delete(SessionDb, SessionTicket).

purge_sessions(SessionDb) ->
    Now = erlang:system_time(seconds),
    NumDeleted =
        ets:select_delete(
          SessionDb, [{#session{valid_until = '$1'},
                       [{'/=', '$1', undefined}, {'>', Now, '$1'}],
                       [true]}]),
    ?dbg_log({purged_sessions, NumDeleted}).

%%
%% Keydir database primitives
%%

new_keydir_db(KeydirDir) ->
    File = filename:join([KeydirDir, ?MODULE]),
    {ok, FileDb} =
        dets:open_file(
          ?MODULE, [{file, ?b2l(File)}, {keypos, #keydir_key.key_id}]),
    Db = ets:new(?MODULE, [public, {keypos, #keydir_key.key_id}]),
    Db = dets:to_ets(FileDb, Db),
    {Db, FileDb}.

keydir_create({Db, FileDb}, Key) ->
    case ets:lookup(Db, Key#keydir_key.key_id) of
        [] ->
            keydir_update({Db, FileDb}, Key);
        [_] ->
            {error, already_exists}
    end.

keydir_read({Db, _FileDb}, {key_id, KeyId}) ->
    ets:lookup(Db, KeyId);
keydir_read({Db, _FileDb}, #{key_id := KeyId,
                             fingerprint := undefined,
                             user_id := undefined,
                             nym := undefined,
                             given_name := undefined,
                             personal_number := undefined,
                             verified := Verified})
  when KeyId /= undefined ->
    case ets:lookup(Db, KeyId) of
        [#keydir_key{verified = Verified} = Key] ->
            [Key];
        [Key] when Verified == undefined ->
            [Key];
        _ ->
            []
    end;
keydir_read({Db, _FileDb}, #{key_id := KeyIdFilter,
                             fingerprint := FingerprintFilter,
                             user_id := UserIdFilter,
                             nym := NymFilter,
                             given_name := GivenNameFilter,
                             personal_number := PersonalNumberFilter,
                             verified := VerifiedFilter}) ->
    ets:foldl(fun(#keydir_key{
                     key_id = KeyId,
                     fingerprint = Fingerprint,
                     user_ids = UserIds,
                     nym = Nym,
                     given_name = GivenName,
                     personal_number = PersonalNumber,
                     verified = Verified} = Key, Acc)
                    when (KeyIdFilter == undefined orelse
                          KeyIdFilter == KeyId) andalso
                         (FingerprintFilter == undefined orelse
                          FingerprintFilter == Fingerprint) andalso
                         (NymFilter == undefined orelse
                          NymFilter == Nym) andalso
                         (GivenNameFilter == undefined orelse
                          GivenNameFilter == GivenName) andalso
                         (PersonalNumberFilter == undefined orelse
                          PersonalNumberFilter == PersonalNumber) andalso
                         (VerifiedFilter == undefined orelse
                          VerifiedFilter == Verified) ->
                      case UserIdFilter of
                          undefined ->
                              [Key|Acc];
                          _ ->
                              case lists:member(UserIdFilter, UserIds) of
                                  true ->
                                      [Key|Acc];
                                  false ->
                                      Acc
                              end
                      end;
                 (_Key, Acc) ->
                      Acc
              end, [], Db).

keydir_update({Db, FileDb}, Key) ->
    true = ets:insert(Db, Key),
    dets:insert(FileDb, Key).

keydir_delete({Db, FileDb}, KeyId) ->
    true = ets:delete(Db, KeyId),
    dets:delete(FileDb, KeyId).

%%
%% Network marshalling tools
%%

parse_json_body(Request, Body) ->
    case rest_util:parse_body(
           Request, Body,
           [{jsone_options, [{object_format, proplist}]}]) of
        {error, _Reason} ->
            throw({error, "Invalid JSON format"});
        JsonValue ->
            JsonValue
    end.

client_ip_address(Socket) ->
    case rester_socket:peername(Socket) of
        {ok, {{127, 0, 0, 1}, _Port}} ->
            get_my_ip_address();
        {ok, {IpAddress, _Port}} ->
            ?l2b(inet:ntoa(IpAddress))
    end.

get_my_ip_address() ->
    case httpc:request("http://ifconfig.me/ip") of
        {ok, {{_Version, 200, _ReasonPhrase}, _Headers, IpAddress}} ->
            ?l2b(IpAddress);
        {error, Reason} ->
            throw(Reason)
    end.

handle_http_response(Socket, Request, {json, Status, JsonValue})
  when is_integer(Status) ->
    json_response(Socket, Request, Status, default_phrase(Status), JsonValue);
handle_http_response(Socket, Request, {json, {Status, Phrase}, JsonValue}) ->
    json_response(Socket, Request, Status, Phrase, JsonValue);
handle_http_response(Socket, Request, Status) when is_integer(Status) ->
    response(Socket, Request, Status, default_phrase(Status));
handle_http_response(Socket, Request, {{Status, Phrase}})
  when is_integer(Status) ->
    response(Socket, Request, Status, Phrase);
handle_http_response(Socket, Request, {Status, ResponseBody})
  when is_integer(Status) ->
    response(Socket, Request, Status, default_phrase(Status), ResponseBody, []);
handle_http_response(Socket, Request, {{Status, Phrase}, ResponseBody}) ->
    response(Socket, Request, Status, Phrase, ResponseBody, []);
handle_http_response(Socket, Request, {Status, ResponseBody, Opts})
  when is_integer(Status) ->
    response(Socket, Request, Status, default_phrase(Status), ResponseBody,
             Opts);
handle_http_response(Socket, Request, {{Status, Phrase}, ResponseBody, Opts}) ->
    response(Socket, Request, Status, Phrase, ResponseBody, Opts).

json_response(Socket, Request, Status, Phrase, JsonValue) ->
    ResponseBody =
        jsone:encode(JsonValue,
                     [{float_format, [{decimals, 4}, compact]},
                      {indent, 2}, {object_key_type, value},
                      {space, 1}, native_forward_slash]),
    rester_http_server:response_r(
      Socket, Request, Status, Phrase, ResponseBody,
      [{content_type, "application/json"}]).

response(Socket, Request, Status, Phrase) ->
    rester_http_server:response_r(
      Socket, Request, Status, Phrase, {skip_body, 0}, []).

response(Socket, Request, Status, Phrase, Body, Opts) ->
    rester_http_server:response_r(Socket, Request, Status, Phrase, Body, Opts).

default_phrase(100) -> "Continue";
default_phrase(101) -> "Switching Protocols";
default_phrase(200) -> "OK";
default_phrase(201) -> "Created";
default_phrase(202) -> "Accepted";
default_phrase(203) -> "Non-Authoritative Information";
default_phrase(204) -> "No Content";
default_phrase(205) -> "Reset Content";
default_phrase(206) -> "Partial Content";
default_phrase(300) -> "Multiple Choices";
default_phrase(301) -> "Moved Permanently";
default_phrase(302) -> "Found";
default_phrase(303) -> "See Other";
default_phrase(304) -> "Not Modified";
default_phrase(305) -> "Use Proxy";
default_phrase(307) -> "Temporary Redirect";
default_phrase(400) -> "Bad Request";
default_phrase(401) -> "Unauthorized";
default_phrase(402) -> "Payment Required";
default_phrase(403) -> "Forbidden";
default_phrase(404) -> "Not Found";
default_phrase(405) -> "Method Not Allowed";
default_phrase(406) -> "Not Acceptable";
default_phrase(407) -> "Proxy Authentication Required";
default_phrase(408) -> "Request Time-out";
default_phrase(409) -> "Conflict";
default_phrase(410) -> "Gone";
default_phrase(411) -> "Length Required";
default_phrase(412) -> "Precondition Failed";
default_phrase(413) -> "Request Entity Too Large";
default_phrase(414) -> "Request-URI Too Large";
default_phrase(415) -> "Unsupported Media Type";
default_phrase(416) -> "Requested range not satisfiable";
default_phrase(417) -> "Expectation Failed";
default_phrase(500) -> "Internal Server Error";
default_phrase(501) -> "Not Implemented";
default_phrase(502) -> "Bad Gateway";
default_phrase(503) -> "Service Unavailable";
default_phrase(504) -> "Gateway Time-out";
default_phrase(505) -> "HTTP Version not supported".

%%
%% Misc utilities
%%

hexstr_to_bin(S) ->
    hexstr_to_bin(S, []).
hexstr_to_bin([], Acc) ->
    list_to_binary(lists:reverse(Acc));
hexstr_to_bin([X,Y|T], Acc) ->
    {ok, [V], []} = io_lib:fread("~16u", [X, Y]),
    hexstr_to_bin(T, [V|Acc]);
hexstr_to_bin([X|T], Acc) ->
    {ok, [V], []} = io_lib:fread("~16u", lists:flatten([X, "0"])),
    hexstr_to_bin(T, [V|Acc]).

conditional_base64_decode(undefined) ->
    undefined;
conditional_base64_decode(Bin) ->
    base64:decode(Bin).
