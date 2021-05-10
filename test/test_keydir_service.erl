-module(test_keydir_service).
-export([start/0, start/1]).
-export([password_login/1, bank_id_login/1]).

-include_lib("apptools/include/shorthand.hrl").
-include("../include/keydir_service.hrl").

-define(PASSWORD, <<"mortuta42">>).
-define(PERSONAL_NUMBER, <<"201701012393">>).

start() ->
    start(password).

start(LoginMode) ->
    AliceKeyFilename =
        case LoginMode of
            password ->
                "alice.key";
            bank_id ->
                "alice-bank-id.key"
        end,
    
    {ok, AliceKey} = file:read_file(AliceKeyFilename),
    {_AliceFingerprint,
     EncodedAliceFingerprint,
     _AliceKeyId,
     EncodedAliceKeyId,
     _AliceNym} =
        key_extract(AliceKey),
    
    {ok, BobKey} = file:read_file("bob.key"),
    {_BobFingerprint,
     EncodedBobFingerprint,
     _BobKeyId,
     _EncodedBobKeyId,
     _BobNym} =
        key_extract(BobKey),
    
    {ok, ChuckKey} = file:read_file("chuck.key"),
    {_ChuckFingerprint,
     EncodedChuckFingerprint,
     _ChuckKeyId,
     EncodedChuckKeyId,
     _ChuckNym} =
        key_extract(ChuckKey),
    
    {ok, FredKey} = file:read_file("fred.key"),
    {_FredFingerprint,
     _EncodedFredFingerprint,
     _FredKeyId,
     _EncodedFredKeyId,
     _FredNym} =
        key_extract(FredKey),
    
    %%
    io:format("**** Read a non-existing key (should fail)\n"),
    {ok, 404, #{<<"errorMessage">> := <<"No such key">>}} =
        json_post(
          "https://127.0.0.1:4436/read",
          #{<<"fingerprint">> => EncodedAliceFingerprint}),
    
    %%
    io:format("**** Login as Bob\n"),
    {ok, BobSessionTicket} = password_login(EncodedBobFingerprint),
    
    %%
    io:format("**** Try to create a key with a mismatched fingerprint\n"),
    {ok, 401, #{<<"errorMessage">> :=
                    <<"Fingerprint does not match login credentials">>}} =
        json_post("https://127.0.0.1:4436/create",
                  #{<<"sessionTicket">> => BobSessionTicket,
                    <<"key">> => AliceKey}),
    %%
    io:format("**** Create Bob's key\n"),
    {ok, 200} =
        json_post("https://127.0.0.1:4436/create",
                  #{<<"sessionTicket">> => BobSessionTicket,
                    <<"key">> => BobKey}),
    
    %%
    io:format("**** Login as Chuck\n"),
    {ok, ChuckSessionTicket} = password_login(EncodedChuckFingerprint),
    
    %%
    io:format("**** Create Chuck's key\n"),
    {ok, 200} =
        json_post("https://127.0.0.1:4436/create",
                  #{<<"sessionTicket">> => ChuckSessionTicket,
                    <<"key">> => ChuckKey}),
    
    %%
    io:format("**** Logout Bob\n"),
    {ok, 200} =
        json_post("https://127.0.0.1:4436/logout",
                  #{<<"sessionTicket">> => BobSessionTicket}),
    
    %%
    io:format("**** Logout Bob again (should fail)\n"),
    {ok, 403, #{<<"errorMessage">> := <<"No such session">>}} =
        json_post("https://127.0.0.1:4436/logout",
                  #{<<"sessionTicket">> => BobSessionTicket}),
    
    %%
    io:format("**** Login as Alice\n"),
    {ok, AliceSessionTicket} =
        case LoginMode of
            password ->
                password_login(EncodedAliceFingerprint);
            bank_id ->
                bank_id_login(EncodedAliceFingerprint)
        end,
    
    %%
    io:format("**** Create Alice'a key with Bob's stale session ticket\n"),
    {ok, 403, #{<<"errorMessage">> := <<"No active session">>}} =
        json_post("https://127.0.0.1:4436/create",
                  #{<<"sessionTicket">> => BobSessionTicket,
                    <<"key">> => AliceKey}),
    
    %%
    io:format("**** Create Alice's key\n"),
    {ok, 200} =
        json_post("https://127.0.0.1:4436/create",
                  #{<<"sessionTicket">> => AliceSessionTicket,
                    <<"key">> => AliceKey}),
    
    %%
    io:format("**** Create Alice's key again (should fail)\n"),
    {ok, 303, #{<<"errorMessage">> := <<"Key already exists">>}} =
        json_post("https://127.0.0.1:4436/create",
                  #{<<"sessionTicket">> => AliceSessionTicket,
                    <<"key">> => AliceKey}),
    
    %%
    io:format("**** Read Alice's key\n"),
    {ok, 200, AliceKey} =
        json_post(
          "https://127.0.0.1:4436/read",
          #{<<"fingerprint">> => EncodedAliceFingerprint,
            <<"verified">> => (LoginMode == bank_id)}),
    
    %%
    io:format("**** Read Alice's key with the help of Alice's User ID "
              "(Chuck's key will returned as well!)\n"),
    {ok, 200, #{<<"keys">> := MatchingUserIdAliceKeys}} =
        json_post(
          "https://127.0.0.1:4436/read",
          #{<<"userId">> => <<"alice">>}),
    case LoginMode of
        password ->
            [#{<<"fingerprint">> := EncodedChuckFingerprint,
               <<"keyId">> := EncodedChuckKeyId,
               <<"nym">> := <<"alice">>,
               <<"userIds">> := [<<"alice">>,<<"bob">>],
               <<"verified">> := false},
             #{<<"fingerprint">> := EncodedAliceFingerprint,
               <<"keyId">> := EncodedAliceKeyId,
               <<"nym">> := <<"alice">>,
               <<"userIds">> := [<<"alice">>],
               <<"verified">> := false}] =
                lists:sort(MatchingUserIdAliceKeys);
        bank_id ->
            [#{<<"keyId">> := EncodedChuckKeyId,
               <<"fingerprint">> := EncodedChuckFingerprint,
               <<"nym">> := <<"alice">>,
               <<"userIds">> := [<<"alice">>,<<"bob">>],
               <<"verified">> := false},
             #{<<"keyId">> := EncodedAliceKeyId,
               <<"fingerprint">> := EncodedAliceFingerprint,
               <<"nym">> := <<"alice">>,
               <<"personalNumber">> := <<"201701012393">>,
               <<"userIds">> := [<<"alice">>],
               <<"verified">> := true}] =
                lists:sort(MatchingUserIdAliceKeys)
    end,
    
    %%
    io:format("**** Read Alice's key with the help of Alice's User ID *and* "
              "fingerprint\n"),
    {ok, 200, AliceKey} =
        json_post(
          "https://127.0.0.1:4436/read",
          #{<<"fingerprint">> => EncodedAliceFingerprint,
            <<"userId">> => <<"alice">>}),
    
    %%
    io:format("**** Read Alice's key with the help of Alice's Nym (Chuck's "
              "key will returned as well!)\n"),
    {ok, 200, #{<<"keys">> := MatchingNymAliceKeys}} =
        json_post(
          "https://127.0.0.1:4436/read",
          #{<<"nym">> => <<"alice">>}),
    case LoginMode of
        password ->
            [#{<<"fingerprint">> := EncodedChuckFingerprint,
               <<"keyId">> := EncodedChuckKeyId,
               <<"nym">> := <<"alice">>,
               <<"userIds">> := [<<"alice">>,<<"bob">>],
               <<"verified">> := false},
             #{<<"fingerprint">> := EncodedAliceFingerprint,
               <<"keyId">> := EncodedAliceKeyId,
               <<"nym">> := <<"alice">>,
               <<"userIds">> := [<<"alice">>],
               <<"verified">> := false}] =
                lists:sort(MatchingNymAliceKeys);
        bank_id ->
            [#{<<"keyId">> := EncodedChuckKeyId,
               <<"fingerprint">> := EncodedChuckFingerprint,
               <<"nym">> := <<"alice">>,
               <<"userIds">> := [<<"alice">>,<<"bob">>],
               <<"verified">> := false},
             #{<<"keyId">> := EncodedAliceKeyId,
               <<"fingerprint">> := EncodedAliceFingerprint,
               <<"nym">> := <<"alice">>,
               <<"personalNumber">> := <<"201701012393">>,
               <<"userIds">> := [<<"alice">>],
               <<"verified">> := true}] =
                lists:sort(MatchingNymAliceKeys)
    end,
    
    %%
    io:format("**** Read a non-exsting key using manual HKP lookup/get (should fail)\n"),
    {ok, 404} =
        http_get(
          "https://127.0.0.1:4436/pks/lookup?op=get&search=0xfeedbabeff"),
    
    %%
    io:format("**** Read Alice's key using manual HKP lookup/get\n"),
    {ok, 200, AliceKey} =
        http_get("https://127.0.0.1:4436/pks/lookup?op=get&search=0x" ++
                     ?b2l(EncodedAliceKeyId)),
    
    %%
    io:format("**** Search Alice's key using manual HKP lookup/index\n"),
    {ok, 200, #{<<"keys">> :=
                    [#{<<"fingerprint">> := EncodedAliceFingerprint,
                       <<"keyId">> := EncodedAliceKeyId,
                       <<"nym">> := <<"alice">>,
                       <<"userIds">> := [<<"alice">>],
                       <<"verified">> := false}]}} =
        http_get("https://127.0.0.1:4436/pks/lookup?op=index&search=0x" ++
                     ?b2l(EncodedAliceKeyId)),
    
    %%
    io:format("**** Create Fred's key using manual HKP\n"),
    {ok, 200} = http_post("https://127.0.0.1:4436/pks/add", FredKey),
    
    %%
    io:format("**** Create Fred's key again with HKP (should fail)\n"),
    {ok, 303, #{<<"errorMessage">> := <<"Key already exists">>}} =
        http_post("https://127.0.0.1:4436/pks/add", FredKey),
    
    %%
    io:format("**** Delete Alice's key using Chuck's session ticket "
              "(should fail)\n"),
    {ok, 403, #{<<"errorMessage">> := <<"Session mismatch">>}} =
        json_post(
           "https://127.0.0.1:4436/delete",
          #{<<"sessionTicket">> => ChuckSessionTicket,
            <<"fingerprint">> => EncodedAliceFingerprint}),
    
    %%
    io:format("**** Logout Chuck\n"),
    {ok, 200} =
        json_post("https://127.0.0.1:4436/logout",
                  #{<<"sessionTicket">> => ChuckSessionTicket}),
    
    %%
    io:format("**** Read Alice's key using gpg command tool\n"),
    Command = "gpg --dry-run --keyserver hkp://localhost:4436 --recv-keys " ++
        ?b2l(EncodedAliceKeyId) ++ " 2>&1",
    io:format("COMMAND: ~p\n", [Command]),
    ok = os:cmd(Command).
    
password_login(EncodedFingerprint) ->
    {ok, 200, #{<<"sessionTicket">> := SessionTicket}} =
        json_post("https://127.0.0.1:4436/passwordLogin",
                  #{<<"fingerprint">> => EncodedFingerprint,
                    <<"password">> => ?PASSWORD}),
    {ok, SessionTicket}.

bank_id_login(EncodedFingerprint) ->
    bank_id_auth(EncodedFingerprint).

bank_id_auth(EncodedFingerprint) ->
    {ok, 200, #{<<"sessionTicket">> := SessionTicket}} =
        json_post("https://127.0.0.1:4436/bankIdAuth",
                  #{<<"fingerprint">> => EncodedFingerprint,
                    <<"personalNumber">> => ?PERSONAL_NUMBER}),
    bank_id_collect(SessionTicket).

bank_id_collect(SessionTicket) ->
    case json_post("https://127.0.0.1:4436/bankIdCollect",
                   #{<<"sessionTicket">> => SessionTicket}) of
        {ok, 200, #{<<"status">> := <<"pending">>,
                    <<"hintCode">> := HintCode}} ->
            io:format("** COLLECT: pending (~p)\n", [HintCode]),
            timer:sleep(2000),
            bank_id_collect(SessionTicket);
        {ok, 200, #{<<"status">> := <<"failed">>,
                    <<"hintCode">> := HintCode}} ->
            io:format("** COLLECT: failed (~p)\n", [HintCode]),
            {error, failed};
        {ok, 200, #{<<"status">> := <<"complete">>}} ->
            io:format("** COLLECT: complete\n"),
            {ok, SessionTicket}
    end.

%%
%% Helpers
%%

json_post(Url, JsonValue) ->
    RequestBody =
        jsone:encode(JsonValue,
                     [{float_format, [{decimals, 4}, compact]},
                      {indent, 2},
                      {object_key_type, value},
                      {space, 1},
                      native_forward_slash]),
    io:format("URL: ~s\n", [Url]),
    io:format("BODY: ~s\n", [RequestBody]),
    case httpc:request(
           post,
           {Url, [], "application/json", RequestBody},
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
    
http_get(Url) ->
    io:format("URL: ~s\n", [Url]),
    case httpc:request(get, {Url, []}, [{timeout, 120 * 1000}],
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

http_post(Url, Body) ->
    io:format("URL: ~s\n", [Url]),
    case httpc:request(
           post,
           {Url, [], "application/octet-stream", Body},
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

key_extract(ArmoredKey) ->
    {ok, #keydir_key{fingerprint = Fingerprint,
                     key_id = KeyId,
                     nym = Nym}} = keydir_pgp:decode_key(ArmoredKey),
    {Fingerprint,
     keydir_service:bin_to_hexstr(Fingerprint),
     KeyId,
     keydir_service:bin_to_hexstr(KeyId),
     Nym}.
