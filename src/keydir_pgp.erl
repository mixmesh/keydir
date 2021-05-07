-module(keydir_pgp).
-export([decode_key/1]).

-include("../include/keydir_service.hrl").

%%
%% Exported: decode_key
%%

decode_key(ArmoredPgpKey) ->
    case pgp_armor:decode(ArmoredPgpKey) of
        {ok, _Opt, PgpKey} ->
            build_keydir_key(pgp_parse:decode_stream(PgpKey));
        {error, Reason} ->
            {error, Reason}
    end.

build_keydir_key(DecodedPgpKey) ->
    build_keydir_key(DecodedPgpKey, {[], #keydir_key{}}).

build_keydir_key([], {UserIds, Key}) ->
    case get_nym(UserIds, Key) of
        {ok, Nym} ->
            {ok, Key#keydir_key{user_ids = lists:reverse(UserIds), nym = Nym}};
        {error, Reason} ->
            {error, Reason}
    end;
build_keydir_key([{key, #{key_data := KeyData}}|Rest], {UserIds, Key}) ->
    build_keydir_key(Rest, {UserIds,
                            Key#keydir_key{
                              fingerprint = pgp_parse:fingerprint(KeyData)}});
build_keydir_key([{user_id, #{value := <<"MIXMESH-NYM:", Nym/binary>>}}|Rest],
                 {UserIds, Key}) ->
    build_keydir_key(Rest, {UserIds, Key#keydir_key{nym = Nym}});
build_keydir_key([{user_id,
                   #{value :=
                         <<"MIXMESH-GIVEN-NAME:", GivenName/binary>>}}|Rest],
                 {UserIds, Key}) ->
    build_keydir_key(Rest, {UserIds, Key#keydir_key{given_name = GivenName}});
build_keydir_key([{user_id,
                   #{value :=
                         <<"MIXMESH-PERSONAL-NUMBER:",
                           PersonalNumber/binary>>}}|Rest],
                 {UserIds, Key}) ->
    build_keydir_key(Rest, {UserIds, Key#keydir_key{
                                       personal_number = PersonalNumber}});
build_keydir_key([{user_id, #{value := UserId}}|Rest], {UserIds, Key}) ->
    build_keydir_key(Rest, {[UserId|UserIds], Key});
build_keydir_key([_|Rest], Acc) ->
    build_keydir_key(Rest, Acc).

get_nym([], #keydir_key{nym = undefined}) ->
    {error, nym_is_missing};
get_nym(_RemaininUserIds, #keydir_key{nym = Nym}) when Nym /= undefined ->
    {ok, Nym};
get_nym([UserId|_], _Key) ->
    {ok, UserId}.
