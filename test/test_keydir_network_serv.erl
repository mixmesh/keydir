-module(test_keydir_network_serv).
-export([start/0]).

-include("../include/keydir_network_client.hrl").
-include("../include/keydir_serv.hrl").

start() ->
    KeydirUser = #keydir_user{
                    nym = <<"foo">>,
                    password = <<"baz">>,
                    email = <<"mrx@gmail.com">>,
                    public_key = #pk{nym = <<"foo">>, h = 0}},
    Options = #keydir_network_client_options{
                 keydir_access = {tcp_only, {{127, 0, 0, 1}, 11112}}},
    ok = keydir_network_client:create(KeydirUser, Options, infinity),
    {error, <<"User already exists">>} =
        keydir_network_client:create(KeydirUser, Options, infinity),
    {error, <<"No such user">>} =
        keydir_network_client:read(<<"fubar">>, Options, infinity),
    AnonymizedKeydirUser = KeydirUser#keydir_user{email = <<>>, password = <<>>},
    {ok, AnonymizedKeydirUser} =
        keydir_network_client:read(<<"foo">>, Options, infinity),
    ok = keydir_network_client:update(KeydirUser, Options, infinity),
    {error, <<"Permission denied">>} =
        keydir_network_client:update(KeydirUser#keydir_user{password = <<"zip">>},
                                     Options, infinity),
    {error, <<"Permission denied">>} =
        keydir_network_client:delete(<<"foo">>, <<"zip">>, Options, infinity),
    ok = keydir_network_client:delete(<<"foo">>, <<"baz">>, Options, infinity),
    {error, <<"No such user">>} =
        keydir_network_client:read(<<"foo">>, Options, infinity).
