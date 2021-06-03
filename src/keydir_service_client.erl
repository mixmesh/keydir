-module(keydir_service_client).
-export([json_post/2, read/2, publish/3]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("elgamal/include/elgamal.hrl").

-define(KEYDIR_PUSHBACK_TIME, 10000).

%%
%% Exported: json_post
%%

json_post(Url, JsonValue) ->
    RequestBody =
        jsone:encode(JsonValue,
                     [{float_format, [{decimals, 4}, compact]},
                      {indent, 2},
                      {object_key_type, value},
                      {space, 1},
                      native_forward_slash]),
    ?dbg_log({json_post, Url, RequestBody}),
    case httpc:request(
           post,
           {Url, [{"Connection", "close"}], "application/json", RequestBody},
           [{timeout, 120 * 1000}],
           [{body_format, binary}]) of
        {ok, {{_Version, StatusCode, _ReasonPhrase}, _Headers, <<>>}} ->
            {ok, StatusCode};
        {ok, {{_Version, StatusCode, _ReasonPhrase}, Headers, ResponseBody}} ->
            case lists:keysearch("content-type", 1, Headers) of
                {value, {_, "application/json"}} ->
                    {ok, StatusCode, jsone:decode(ResponseBody)};
                _ ->
                    {ok, StatusCode, ResponseBody}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

stringify_host(Atom) when is_atom(Atom) ->
    ?a2l(Atom);
stringify_host(String) when is_list(String) ->
    String;
stringify_host({A, B, C, D}) ->
    ?i2l(A) ++ "." ++ ?i2l(B) ++ "." ++ ?i2l(C) ++ "." ++ ?i2l(D).

%%
%% Exported: read
%%

-spec read(keydir_service:access(),
           {fingerprint, keydir_service:fingerprint()} |
           {nym, keydir_service:nym()}) ->
          {ok, #pk{}} |
          {error,
           pgp_armor:decode_error_reason() |
           ambigous_keys_not_supported |
           {error_message, Status :: integer(), ErrorMessage :: binary()} |
           {unexpected_response, Status :: integer(), ResponseBody :: term()} |
           {transport, term()}}.

read({Host, Port} = Access, Filter) ->
    ?dbg_log({read, Access, Filter}),
    Url = "https://" ++ stringify_host(Host) ++ ":" ++ ?i2l(Port) ++ "/read",
    JsonValue =
        case Filter of
            {fingerprint, Value} ->
                #{<<"fingerprint">> => keydir_service:bin_to_hexstr(Value)};
            {nym, Value} ->
                #{<<"nym">> => keydir_service:bin_to_hexstr(Value)}
        end,
    case json_post(Url, JsonValue) of
        {ok, 200, ArmoredPgpKey} when is_binary(ArmoredPgpKey) ->
            case pgp_armor:decode(ArmoredPgpKey) of
                {ok, _Opt, EncodedPgpKey} ->
                    keydir_pgp:key_to_pk(EncodedPgpKey);
                {error, Reason} ->
                    {error, Reason}
            end;
        {ok, 200, PgpKeyList} when is_list(PgpKeyList) ->
            {error, ambigous_keys_not_supported};
        {ok, Status, #{<<"errorMessage">> := ErrorMessage}} ->
            {error, {error_message, Status, ErrorMessage}};
        {ok, Status, ResponseBody} ->
            {error, {unexpected_response, Status, ResponseBody}};
        {error, Reason} ->
            {error, {transport, Reason}}
    end.

%%
%% Exported: publish
%%

-spec publish(keydir_service:access(), keydir_service:password(), #pk{}) ->
          ok.

publish(Access, Password, Pk) ->
    ?dbg_log({publish, Access, Password, Pk}),
    {ok, Fingerprint, PgpKey} = keydir_pgp:pk_to_key(Pk),
    publish(Access, Password, Pk, Fingerprint, PgpKey, undefined).

publish(Access, Password, Pk, Fingerprint, PgpKey, undefined) ->
    case password_login(Access, Fingerprint, Password) of
        {ok, SessionTicket} ->
            publish(Access, Password, Pk, Fingerprint, PgpKey, SessionTicket);
        {error, Reason} ->
            ?daemon_log_tag_fmt(
               system,
               "Could not login to the Keydir service (~p). "
               "Will try again in ~w seconds.",
               [Reason, trunc(?KEYDIR_PUSHBACK_TIME / 1000)]),
            ?dbg_log({password_login_failed, Reason}),
            timer:sleep(?KEYDIR_PUSHBACK_TIME),
            publish(Access, Password, Pk, Fingerprint, PgpKey, undefined)
    end;
publish(Access, Password, Pk, Fingerprint, PgpKey, SessionTicket) ->
    case read(Access, {fingerprint, Fingerprint}) of
        {ok, Pk} ->
            ?daemon_log_tag_fmt(system, "Keydir service is in sync", []),
            ok;
        {ok, _StalePk} ->
            case update(Access, SessionTicket, Pk) of
                ok  ->
                    ?daemon_log_tag_fmt(
                       system, "Updated the Keydir service", []),
                    ok;
                {error, no_active_session} ->
                    publish(Access, Password, Pk, Fingerprint, PgpKey,
                            undefined);
                {error, Reason} ->
                    ?daemon_log_tag_fmt(
                       system,
                       "Could not update the Keydir service (~p). "
                       "Will try again in ~w seconds.",
                       [Reason, trunc(?KEYDIR_PUSHBACK_TIME / 1000)]),
                    ?dbg_log({update_failed, Reason}),
                    timer:sleep(?KEYDIR_PUSHBACK_TIME),
                    publish(Access, Password, Pk, Fingerprint, PgpKey,
                            SessionTicket)
            end;
        {error, {error_message, 404, <<"No such key">>}} ->
            case create(Access, SessionTicket, Pk) of
                ok  ->
                    ?daemon_log_tag_fmt(
                       system, "Updated the Keydir service", []),
                    ok;
                {error, no_active_session} ->
                    publish(Access, Password, Pk, Fingerprint, PgpKey,
                            undefined);
                {error, Reason} ->
                    ?daemon_log_tag_fmt(
                       system,
                       "Could not create a key in the Keydir service (~p). "
                       "Will try again in ~w seconds.",
                       [Reason, trunc(?KEYDIR_PUSHBACK_TIME / 1000)]),
                    ?dbg_log({create_failed, Reason}),
                    timer:sleep(?KEYDIR_PUSHBACK_TIME),
                    publish(Access, Password, Pk, Fingerprint, PgpKey,
                            SessionTicket)
            end;
        {error, Reason} ->
            ?daemon_log_tag_fmt(
               system,
               "Could not contact the Keydir service (~p). "
               "Will try again in ~w seconds.",
               [Reason, trunc(?KEYDIR_PUSHBACK_TIME / 1000)]),
            ?dbg_log({read_failed, Reason}),
            timer:sleep(?KEYDIR_PUSHBACK_TIME),
            publish(Access, Password, Pk, Fingerprint, PgpKey, SessionTicket)
    end.

password_login({Host, Port} = Access, Fingerprint, Password) ->
    ?dbg_log({password_login, Access, Fingerprint, Password}),
    Url = "https://" ++ stringify_host(Host) ++ ":" ++ ?i2l(Port) ++
        "/passwordLogin",
    case json_post(Url, #{<<"fingerprint">> =>
                              keydir_service:bin_to_hexstr(Fingerprint),
                          <<"password">> => Password}) of
        {ok, 200, #{<<"sessionTicket">> := SessionTicket}} ->
            {ok, base64:decode(SessionTicket)};
        {ok, Status, #{<<"errorMessage">> := ErrorMessage}} ->
            {error, {error_message, Status, ErrorMessage}};
        {ok, Status, ResponseBody} ->
            {error, {unexpected_response, Status, ResponseBody}};
        {error, Reason} ->
            {error, {transport, Reason}}
    end.

create({Host, Port} = Access, SessionTicket, Pk) ->
    ?dbg_log({create, Access, SessionTicket, Pk}),
    Url = "https://" ++ stringify_host(Host) ++ ":" ++ ?i2l(Port) ++ "/create",
    insert(SessionTicket, Pk, Url).

insert(SessionTicket, Pk, Url) ->
    {ok, ArmoredPgpKey} = pk_to_armored_key(Pk),
    JsonValue =
        #{<<"sessionTicket">> => base64:encode(SessionTicket),
          <<"key">> => ArmoredPgpKey},
    case json_post(Url, JsonValue) of
        {ok, 200} ->
            ok;
        {ok, 403, #{<<"errorMessage">> := <<"No active session">>}} ->
            {error, no_active_session};
        {ok, Status, #{<<"errorMessage">> := ErrorMessage}} ->
            {error, {error_message, Status, ErrorMessage}};
        {ok, Status, ResponseBody} ->
            {error, {unexpected_response, Status, ResponseBody}};
        {error, Reason} ->
            {error, {transport, Reason}}
    end.

pk_to_armored_key(Pk) ->
    {ok, _Fingerprint, PgpKey} = keydir_pgp:pk_to_key(Pk),
    {ok, ?l2b(pgp_armor:encode_pubkey(PgpKey))}.

update({Host, Port} = Access, SessionTicket, Pk) ->
    ?dbg_log({create, Access, SessionTicket, Pk}),
    Url = "https://" ++ stringify_host(Host) ++ ":" ++ ?i2l(Port) ++ "/update",
    insert(SessionTicket, Pk, Url).
