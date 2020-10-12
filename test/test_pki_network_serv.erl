-module(test_pki_network_serv).
-export([start/0]).

-include_lib("pki/include/pki_network_client.hrl").
-include_lib("pki/include/pki_serv.hrl").

start() ->
    PkiUser = #pki_user{
                 name = <<"foo">>,
                 password = <<"baz">>,
                 email = <<"mrx@gmail.com">>,
                 public_key = belgamal:binary_to_public_key(<<"=">>)},
    Options = #pki_network_client_options{
                 pki_access = {tcp_only, {{127, 0, 0, 1}, 11112}}},
    ok = pki_network_client:create(PkiUser, Options, infinity),
    {error, <<"User already exists">>} =
        pki_network_client:create(PkiUser, Options, infinity),
    {error, <<"No such user">>} =
        pki_network_client:read(<<"fubar">>, Options, infinity),
    AnonymizedPkiUser = PkiUser#pki_user{email = <<>>, password = <<>>},
    {ok, AnonymizedPkiUser} =
        pki_network_client:read(<<"foo">>, Options, infinity),
    ok = pki_network_client:update(PkiUser, Options, infinity),
    {error, <<"Permission denied">>} =
        pki_network_client:update(PkiUser#pki_user{password = <<"zip">>},
                                  Options, infinity),
    {error, <<"Permission denied">>} =
        pki_network_client:delete(<<"foo">>, <<"zip">>, Options, infinity),
    ok = pki_network_client:delete(<<"foo">>, <<"baz">>, Options, infinity),
    {error, <<"No such user">>} =
        pki_network_client:read(<<"foo">>, Options, infinity).
