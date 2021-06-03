-module(test_keydir_serv).
-export([start/0]).

-include("../include/keydir_serv.hrl").

start() ->
    KeydirUser = #keydir_user{nym = <<"foo">>,
                              password = <<"baz">>,
                              public_key = #pk{nym = <<"foo">>, h = 0}},
    ok = keydir_serv:create(KeydirUser),
    {error, user_already_exists} = keydir_serv:create(KeydirUser),
    {error, no_such_user} = keydir_serv:read(<<"fubar">>),
    {ok, KeydirUser} = keydir_serv:read(<<"foo">>),
    ok = keydir_serv:update(KeydirUser),
    {error, permission_denied} =
        keydir_serv:update(KeydirUser#keydir_user{password = <<"zip">>}),
    {error, permission_denied} = keydir_serv:delete(<<"foo">>, <<"zip">>),
    ok = keydir_serv:delete(<<"foo">>, <<"baz">>),
    {error, no_such_user} = keydir_serv:read(<<"foo">>).
