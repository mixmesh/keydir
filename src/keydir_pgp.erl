-module(keydir_pgp).
-export([decode_key/1]).
-export([nym_user_id/1, given_name_user_id/1, personal_number_user_id/1]).

-include("../include/keydir_service.hrl").

%%
%% Exported: decode_key
%%

decode_key(EncodedKey) ->
    #{<<"fingerprint">> := EncodedFingerprint,
      <<"userIds">> := UserIds} =
        jsone:decode(base64:decode(EncodedKey)),
    {RemainingUserIds, Key} = parse_user_ids(UserIds),
    case get_nym(RemainingUserIds, Key) of
        {ok, Nym} ->
            {ok, Key#keydir_key{fingerprint = base64:decode(EncodedFingerprint),
                                user_ids = RemainingUserIds,
                                nym = Nym}};
        {error, Reason} ->
            {error, Reason}
    end.

parse_user_ids(UserIds) ->
    parse_user_ids(UserIds, {[], #keydir_key{}}).

parse_user_ids([], {RemainingUserIds, Key}) ->
    {lists:reverse(RemainingUserIds), Key};
parse_user_ids([<<"MIXMESH-NYM:", Nym/binary>>|Rest],
               {RemainingUserIds, Key}) -> 
    parse_user_ids(Rest, {RemainingUserIds, Key#keydir_key{nym = Nym}});
parse_user_ids([<<"MIXMESH-GIVEN-NAME:", GivenName/binary >>|Rest],
               {RemainingUserIds, Key}) -> 
    parse_user_ids(Rest, {RemainingUserIds,
                          Key#keydir_key{given_name = GivenName}});
parse_user_ids([<<"MIXMESH-PERSONAL-NUMBER:", PersonalNumber/binary >>|Rest],
               {RemainingUserIds, Key}) -> 
    parse_user_ids(Rest, {RemainingUserIds,
                          Key#keydir_key{personal_number = PersonalNumber}});
parse_user_ids([UserId|Rest], {RemainingUserIds, Key}) -> 
    parse_user_ids(Rest, {[UserId|RemainingUserIds], Key}).

get_nym([], #keydir_key{nym = undefined}) ->
    {error, nym_is_missing};
get_nym(_RemaininUserIds, #keydir_key{nym = Nym}) when Nym /= undefined ->
    {ok, Nym};
get_nym([UserId|_], _Key) ->
    {ok, UserId}.

%%
%% Exported: nym_user_id (used by test suite)
%%

nym_user_id(Nym) ->
    << <<"MIXMESH-NYM:">>/binary, Nym/binary >>.

%%
%% Exported: given_name_user_id (used by test suite)
%%

given_name_user_id(GivenName) ->
    << <<"MIXMESH-GIVEN-NAME:">>/binary, GivenName/binary >>.

%%
%% Exported: personal_number_user_id (used by test suite)
%%

personal_number_user_id(PersonalNumber) ->
    << <<"MIXMESH-PERSONAL-NUMBER:">>/binary, PersonalNumber/binary >>.
