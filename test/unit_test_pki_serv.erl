-module(unit_test_pki_serv).
-export([start/0]).

-include("../src/pki_serv.hrl").

start() ->
    %% NOTE: For this to work "data-dir" must be set to "/tmp" in obscrete.conf
    file:delete("/tmp/pki_db"),
    User = #user{name = <<"foo">>, 
                 password = <<"baz">>,
                 public_key = <<"=">>},
    ok = pki_serv:create(User),
    {error, user_already_exists} = pki_serv:create(User),
    {error, no_such_user} = pki_serv:read(<<"fubar">>),
    {ok, User} = pki_serv:read(<<"foo">>),
    ok = pki_serv:update(User),
    {error, permission_denied} =
        pki_serv:update(User#user{password = <<"zip">>}),
    {error, permission_denied} = pki_serv:delete(<<"foo">>, <<"zip">>),
    ok = pki_serv:delete(<<"foo">>, <<"baz">>),
    {error, no_such_user} = pki_serv:read(<<"foo">>).
