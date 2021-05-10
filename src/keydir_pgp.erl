-module(keydir_pgp).
-export([decode_key/1]).

-include("../include/keydir_service.hrl").

%%
%% Exported: decode_key
%%

decode_key(ArmoredPgpKey) ->
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
