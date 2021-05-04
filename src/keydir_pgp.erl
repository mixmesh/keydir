-module(keydir_pgp).
-export([decode_key/1, user_attribute_values/2]).

%-type ascii_armored_pgp_key() :: binary().
%-type base64string() :: binary().
%-type user_id() :: binary().
%-type attribute_type() :: pos_integer().
%-type attribute_value() :: binary().

%%
%% Exported: decode_key
%%

%-spec decode_key(asci_armored_pgp_key()) ->
%          {ok, #{<<"keyId">> := base64string(),
%                 <<"userIds">> := [user_id()],
%                 <<"userAttributes">> := #{<<"type">> := attribute_type(),
%                                           <<"value">> := attribute_value()}}} |
%          {error, any()}.

decode_key(EncodedKey) ->
    {ok, jsone:decode(base64:decode(EncodedKey))}.

%%
%% Exported: user_attribute_values
%%

%-spec user_attribute_values([attribute_type()],
%                            [#{<<"type">> := attribute_type(),
%                               <<"value">> := attribute_value()}]) ->
%          [attribute_value()].

user_attribute_values(Types, Attributes) ->
    user_attribute_values(Types, Attributes, []).

user_attribute_values([], _Attributes, Values) ->
    lists:reverse(Values);
user_attribute_values([Type|Rest], Attributes, Values) ->
    case attribute_search(Type, Attributes) of
        {found, Value} ->
            user_attribute_values(Rest, Attributes, [Value|Values]);
        not_found ->
            user_attribute_values(Rest, Attributes, [undefined|Values])
    end.

attribute_search(_Type, []) ->
    not_found;
attribute_search(Type, [#{<<"type">> := Type, <<"value">> := Value}|_]) ->
    {found, Value};
attribute_search(Type, [_|Rest]) ->
    attribute_search(Type, Rest).
