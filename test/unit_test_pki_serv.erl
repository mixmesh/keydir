-module(unit_test_pki_serv).
-export([start/0]).

-include("../include/pki_serv.hrl").

start() ->
    %% NOTE: For this to work "data-dir" must be set to "/tmp" in obscrete.conf
    file:delete("/tmp/pki_db"),
    DbUser = #db_user{name = <<"foo">>, 
                      password = <<"baz">>,
                      public_key = <<"=">>},
    ok = pki_serv:create(DbUser),
    {error, user_already_exists} = pki_serv:create(DbUser),
    {error, no_such_user} = pki_serv:read(<<"fubar">>),
    {ok, DbUser} = pki_serv:read(<<"foo">>),
    ok = pki_serv:update(DbUser),
    {error, permission_denied} =
        pki_serv:update(DbUser#db_user{password = <<"zip">>}),
    {error, permission_denied} = pki_serv:delete(<<"foo">>, <<"zip">>),
    ok = pki_serv:delete(<<"foo">>, <<"baz">>),
    {error, no_such_user} = pki_serv:read(<<"foo">>).
