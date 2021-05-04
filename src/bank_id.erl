-module(bank_id).
-export([auth/2, collect/1, cancel/1]).
-export_types([order_ref/0, hint_code/0, given_name/0, personal_number/0]).

-include_lib("apptools/include/log.hrl").

-define(TEST_BANK_ID_URL, "https://appapi2.test.bankid.com/rp/v5.1").

-type order_ref() :: binary().
-type hint_code() :: binary().
-type given_name() :: binary().
-type personal_number() :: binary().

%%
%% Exported: auth
%%

auth(PersonalNumber, ClientIpAddress) ->
    JsonValue =
        #{<<"personalNumber">> => PersonalNumber,
          <<"endUserIp">> => ClientIpAddress},
    case json_post("/auth", JsonValue) of
        {ok, 200, "OK", #{<<"orderRef">> := OrderRef}} ->
            {ok, OrderRef};
        {ok, Status, Phrase, ResponseJsonValue} ->
            {bad_response, Status, Phrase, ResponseJsonValue};
        {error, Reason} ->
            {http_error, Reason}
    end.

%%
%% Exported: collect
%%

collect(OrderRef) ->
    JsonValue = #{<<"orderRef">> => OrderRef},
    case json_post("/collect", JsonValue) of
        {ok, 200, _Phrase, #{<<"orderRef">> := OrderRef,
                             <<"status">> := <<"pending">>,
                             <<"hintCode">> := HintCode}} ->
            {pending, HintCode};
        {ok, 200, _Phrase, #{<<"orderRef">> := OrderRef,
                             <<"status">> := <<"failed">>,
                             <<"hintCode">> := HintCode}} ->
            {failed, HintCode};
        {ok, 200, _Phrase,
         #{<<"orderRef">> := OrderRef,
           <<"status">> := <<"complete">>,
           <<"completionData">> :=
               #{<<"cert">> :=
                     #{<<"notAfter">> := _NotAfter,
                       <<"notBefore">> := _NotBefore},
                 <<"device">> := #{<<"ipAddress">> := _DeviceIpAddress},
                 <<"ocspResponse">> := _OcspResponse,
                 <<"signature">> := _Signature,
                 <<"user">> :=
                     #{<<"givenName">> := GivenName,
                       <<"name">> := _Name,
                       <<"personalNumber">> := PersonalNumber,
                       <<"surname">> := _Surname}}} = CompletionData} ->
            %% Must be logged according to the BankID Relying Part Guidelines
            ?daemon_log_fmt("Completion data: ~p", [CompletionData]),
            {complete, GivenName, PersonalNumber};
        {ok, Status, Phrase, ResponseJsonValue} ->
            {bad_response, Status, Phrase, ResponseJsonValue};
        {error, Reason} ->
            {http_error, Reason}
    end.

%%
%% Exported: cancel
%%

cancel(OrderRef) ->
    JsonValue = #{<<"orderRef">> => OrderRef},
    case json_post("/cancel", JsonValue) of
        {ok, 200, "OK", #{}} ->
            ok;
        {ok, Status, Phrase, ResponseJsonValue} ->
            {bad_response, Status, Phrase, ResponseJsonValue};
        {error, Reason} ->
            {http_error, Reason}
    end.

%%
%% Helpers
%%

json_post(ExtraUriPath, JsonValue) ->
    Body =
        jsone:encode(JsonValue,
                     [{float_format, [{decimals, 4}, compact]},
                      {indent, 2},
                      {object_key_type, value},
                      {space, 1},
                      native_forward_slash]),
    KeydirPrivDir = code:priv_dir(keydir),
    ?dbg_log({http_request, Body}),
    case httpc:request(
           post,
           {?TEST_BANK_ID_URL ++ ExtraUriPath, [], "application/json", Body},
           [{timeout, 30000},
            {ssl,
             [{verify, verify_peer},
              {cacertfile, filename:join([KeydirPrivDir, "server.crt.pem"])},
              {certfile, filename:join([KeydirPrivDir, "client.crt.pem"])},
              {keyfile, filename:join([KeydirPrivDir, "client.key.pem"])}]}],
           [{body_format, binary}]) of
        {ok, {{_Version, Status, Phrase}, _Headers, ResponseBody}} ->
            {ok, Status, Phrase, jsone:decode(ResponseBody)};
        {error, Reason} ->
            {error, Reason}
    end.
