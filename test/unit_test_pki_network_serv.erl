-module(unit_test_pki_network_serv).
-export([start/0]).

-include("../include/pki_serv.hrl").

start() ->
    DbUser = #db_user{
                name = <<"foo">>, 
                password = <<"baz">>,
                email = <<"mrx@gmail.com">>,
                public_key = belgamal:binary_to_public_key(<<"=">>)},
    ok = pki_network_client:create(DbUser),
    {error, <<"User already exists">>} = pki_network_client:create(DbUser),
    {error, <<"No such user">>} = pki_network_client:read(<<"fubar">>),
    AnonymizedDbUser = DbUser#db_user{email = <<>>, password = <<>>},
    {ok, AnonymizedDbUser} = pki_network_client:read(<<"foo">>),
    ok = pki_network_client:update(DbUser),
    {error, <<"Permission denied">>} =
        pki_network_client:update(DbUser#db_user{password = <<"zip">>}),
    {error, <<"Permission denied">>} =
        pki_network_client:delete(<<"foo">>, <<"zip">>),
    ok = pki_network_client:delete(<<"foo">>, <<"baz">>),
    {error, <<"No such user">>} = pki_network_client:read(<<"foo">>).
