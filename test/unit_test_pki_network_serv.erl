-module(unit_test_pki_network_serv).
-export([start/0]).

-include("../src/pki_serv.hrl").

start() ->
    User = #user{name = <<"foo">>, 
                 password = <<"baz">>,
                 email = <<"mrx@gmail.com">>,
                 public_key = belgamal:binary_to_public_key(<<"=">>)},
    ok = pki_network_client:create(User),
    {error, <<"User already exists">>} = pki_network_client:create(User),
    {error, <<"No such user">>} = pki_network_client:read(<<"fubar">>),
    AnonymizedUser = User#user{email = <<>>, password = <<>>},
    {ok, AnonymizedUser} = pki_network_client:read(<<"foo">>),
    ok = pki_network_client:update(User),
    {error, <<"Permission denied">>} =
        pki_network_client:update(User#user{password = <<"zip">>}),
    {error, <<"Permission denied">>} =
        pki_network_client:delete(<<"foo">>, <<"zip">>),
    ok = pki_network_client:delete(<<"foo">>, <<"baz">>),
    {error, <<"No such user">>} = pki_network_client:read(<<"foo">>).
