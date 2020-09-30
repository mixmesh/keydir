-module(unit_test_pki_network_serv).
-export([start/0]).

-include("../include/pki_serv.hrl").

start() ->
    PkiUser = #pki_user{
                 name = <<"foo">>, 
                 password = <<"baz">>,
                 email = <<"mrx@gmail.com">>,
                 public_key = belgamal:binary_to_public_key(<<"=">>)},
    ok = pki_network_client:create(PkiUser),
    {error, <<"User already exists">>} = pki_network_client:create(PkiUser),
    {error, <<"No such user">>} = pki_network_client:read(<<"fubar">>),
    AnonymizedPkiUser = PkiUser#pki_user{email = <<>>, password = <<>>},
    {ok, AnonymizedPkiUser} = pki_network_client:read(<<"foo">>),
    ok = pki_network_client:update(PkiUser),
    {error, <<"Permission denied">>} =
        pki_network_client:update(PkiUser#pki_user{password = <<"zip">>}),
    {error, <<"Permission denied">>} =
        pki_network_client:delete(<<"foo">>, <<"zip">>),
    ok = pki_network_client:delete(<<"foo">>, <<"baz">>),
    {error, <<"No such user">>} = pki_network_client:read(<<"foo">>).
