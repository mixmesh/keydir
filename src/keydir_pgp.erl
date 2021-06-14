-module(keydir_pgp).
-export([key_to_pk/1, pk_to_key/1, armored_key_to_keydir_key/1,
         format_index/2]).

-include_lib("apptools/include/shorthand.hrl").
-include_lib("elgamal/include/elgamal.hrl").
-include("../include/keydir_service.hrl").

%% Section references can be found in
%% https://tools.ietf.org/pdf/draft-ietf-openpgp-rfc4880bis-10.pdf

%% Section 9.1: Public-Key Algorithms
-define(PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT_OR_SIGN, 1).
-define(PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT, 2).
-define(PUBLIC_KEY_ALGORITHM_RSA_SIGN, 3).
-define(PUBLIC_KEY_ALGORITHM_ELGAMAL, 16).
-define(PUBLIC_KEY_ALGORITHM_DSA, 17).

%%
%% Exported: key_to_pk
%%

key_to_pk(Key) ->
    {Packets, Context} = pgp_parse:decode(Key),
    #{nym := Nym, h := H} = extract_pk_values(Packets, Context, #{}),
    {ok, #pk{nym = Nym, h = H}}.

extract_pk_values([], _Context, Values) ->
    Values;
extract_pk_values([{key, #{key_id := KeyId}}|Rest], Context, Values) ->
    #{y := Y} = maps:get(KeyId, Context),
    extract_pk_values(Rest, Context, Values#{h => Y});
extract_pk_values([{user_id, #{value := Value}}|Rest], Context, Values) ->
    extract_pk_values(Rest, Context, Values#{nym => Value});
extract_pk_values([_|Rest], Context, Values) ->
    extract_pk_values(Rest, Context, Values).

%%
%% Exported: pk_to_key
%%

pk_to_key(Pk) ->
    Key = pk_to_public_encrypt_key(Pk),
    #{key_id := KeyId, fingerprint := Fingerprint} = Key,
    Packets = [{key, #{key_id => KeyId}}, {user_id, #{value => Pk#pk.nym}}],
    {Data, _Context} = pgp_parse:encode_packets(Packets, #{KeyId => Key}),
    {ok, Fingerprint, Data}.

pk_to_public_encrypt_key(#pk{h = H}) ->
    Key = #{type => elgamal,
            use => [encrypt, sign],
            creation => {{1971, 1, 1}, {1, 1, 1}},
            p => ?P,
            q => ?Q,
            g => ?G,
            y => H},
    KeyData = pgp_keys:encode_public_key(Key),
    Fingerprint = pgp_util:fingerprint(KeyData),
    KeyId = pgp_util:fingerprint_to_key_id(Fingerprint),
    Key#{fingerprint => Fingerprint, key_id => KeyId}.

%%
%% Exported: armored_key_to_keydir_key
%%

-spec armored_key_to_keydir_key(ArmoredPgpKey :: binary()) ->
          {ok, #keydir_key{}} |
          {error, badcrc |
                  missing_header |
                  missing_footer |
                  bad_footer |
                  nym_is_missing}.

armored_key_to_keydir_key(ArmoredPgpKey) ->
    case pgp_armor:decode(ArmoredPgpKey) of
        {ok, _Opt, PgpKey} ->
            {DecodedPgpKey, Context} = pgp_parse:decode(PgpKey, #{}),
            build_keydir_key(DecodedPgpKey, Context);
        {error, Reason} ->
            {error, Reason}
    end.

build_keydir_key(DecodedPgpKey, Context) ->
    build_keydir_key(DecodedPgpKey, Context, {[], #keydir_key{}}).

build_keydir_key([], _Context, {UserIds, Key}) ->
    case get_nym(UserIds, Key) of
        {ok, Nym} ->
            {ok, Key#keydir_key{user_ids = lists:reverse(UserIds), nym = Nym}};
        {error, Reason} ->
            {error, Reason}
    end;
build_keydir_key([{key, #{key_id := KeyId}}|Rest], Context, {UserIds, Key}) ->
    #{fingerprint := Fingerprint} = maps:get(KeyId, Context),
    build_keydir_key(
      Rest, Context,
      {UserIds, Key#keydir_key{fingerprint = Fingerprint, key_id = KeyId}});
build_keydir_key(
  [{user_id, #{value := <<"MM-NYM:", Nym/binary>>}}|Rest], Context,
  {UserIds, Key}) ->
    build_keydir_key(Rest, Context, {UserIds, Key#keydir_key{nym = Nym}});
build_keydir_key(
  [{user_id, #{value := <<"MM-GN:", GivenName/binary>>}}|Rest], Context,
  {UserIds, Key}) ->
    build_keydir_key(Rest, Context,
                     {UserIds, Key#keydir_key{given_name = GivenName}});
build_keydir_key(
  [{user_id, #{value := <<"MM-PNO:",  PersonalNumber/binary>>}}|Rest], Context,
  {UserIds, Key}) ->
    build_keydir_key(Rest, Context,
                     {UserIds, Key#keydir_key{
                                 personal_number = PersonalNumber}});
build_keydir_key([{user_id, #{value := UserId}}|Rest], Context,
                 {UserIds, Key}) ->
    build_keydir_key(Rest, Context, {[UserId|UserIds], Key});
build_keydir_key([_|Rest], Context, Acc) ->
    build_keydir_key(Rest, Context, Acc).

get_nym([], #keydir_key{nym = undefined}) ->
    {error, nym_is_missing};
get_nym(_RemaininUserIds, #keydir_key{nym = Nym}) when Nym /= undefined ->
    {ok, Nym};
get_nym([UserId|_], _Key) ->
    {ok, UserId}.

%%
%% Exported: format_index
%%

format_index(ReadArmoredPgpKey, Keys) ->
    ?l2b([<<"info:1:">>, ?i2b(length(Keys)), <<"\n">>|
          format_index_keys(ReadArmoredPgpKey, Keys)]).

format_index_keys(_ReadArmoredPgpKey, []) ->
    [];
format_index_keys(ReadArmoredPgpKey, [Key|Rest]) ->
    {ok, ArmoredPgpKey} = ReadArmoredPgpKey(Key),
    {ok, _Opt, PgpKey} = pgp_armor:decode(ArmoredPgpKey),
    {DecodedPgpKey, Context} = pgp_parse:decode(PgpKey, #{}),
    [format_index_lines(DecodedPgpKey, Context)|
     format_index_keys(ReadArmoredPgpKey, Rest)].

format_index_lines([], _Context) ->
    [];
format_index_lines([{key, #{key_id := KeyId}}|Rest], Context) ->
    Key = maps:get(KeyId, Context),
    [<<"pub:">>,
     format_fingerprint(Key), <<":">>,
     format_key_algo(Key), <<":">>,
     format_keylen(Key), <<":">>,
     format_creationdate(Key), <<":">>,
     format_expirationdate(Key), <<":">>,
     format_flags(Key), <<"\n">>|
     format_index_lines(Rest, Context)];
format_index_lines([{user_id, #{value := UserId}}|Rest], Context) ->
    %% FIXME: According to "Section 5.2: Machine Readable Indexes" we
    %% need to figure out the "creationdate", "expirationdate" and
    %% "flags" from the self-signature (if any) for this uid. I just
    %% leave them empty for now.
    [<<"uid:">>,
     format_uid(UserId), <<":">>,
     format_creationdate(undefined), <<":">>,
     format_expirationdate(undefined), <<":">>,
     format_flags(undefined), <<"\n">>|
     format_index_lines(Rest, Context)];
format_index_lines([_|Rest], Context) ->
    format_index_lines(Rest, Context).

format_fingerprint(#{fingerprint := Fingerprint}) ->
    keydir_service:bin_to_hexstr(Fingerprint);
format_fingerprint(_) ->
    <<>>.

format_key_algo(#{use := [encrypt, sign], type := rsa}) ->
    ?i2b(?PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT_OR_SIGN);
format_key_algo(#{use := [encrypt], type := rsa}) ->
    ?i2b(?PUBLIC_KEY_ALGORITHM_RSA_ENCRYPT);
format_key_algo(#{use := [sign], type := rsa}) ->
    ?i2b(?PUBLIC_KEY_ALGORITHM_RSA_SIGN);
format_key_algo(#{type := dss}) ->
    ?i2b(?PUBLIC_KEY_ALGORITHM_DSA);
format_key_algo(#{type := dsa}) ->
    ?i2b(?PUBLIC_KEY_ALGORITHM_DSA);
format_key_algo(#{type := elgamal}) ->
    ?i2b(?PUBLIC_KEY_ALGORITHM_ELGAMAL);
format_key_algo(_) ->
    <<>>.

format_keylen(_) ->
    %% FIXME: What is the best way to calculate the key length
    <<>>.

format_creationdate(#{creation := Datetime}) ->
    ?i2b(calendar:datetime_to_gregorian_seconds(Datetime));
format_creationdate(_) ->
    <<>>.

format_expirationdate(#{expiration := Datetime}) ->
    ?i2b(calendar:datetime_to_gregorian_seconds(Datetime));
format_expirationdate(_) ->
    <<>>.

format_flags(_) ->
    <<>>.

format_uid(UserId) ->
    uri_string:recompose(#{path => UserId}).
