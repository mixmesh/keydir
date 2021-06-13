-module(keydir_pgp).
-export([key_to_pk/1, pk_to_key/1, armored_key_to_keydir_key/1]).

-include_lib("elgamal/include/elgamal.hrl").
-include("../include/keydir_service.hrl").

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
