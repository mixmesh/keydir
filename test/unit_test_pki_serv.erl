-module(unit_test_pki_serv).
-export([start/0]).

-include("../include/pki_serv.hrl").

start() ->
    PkiUser = #pki_user{name = <<"foo">>, 
                        password = <<"baz">>,
                        public_key = <<"=">>},
    ok = pki_serv:create(PkiUser),
    {error, user_already_exists} = pki_serv:create(PkiUser),
    {error, no_such_user} = pki_serv:read(<<"fubar">>),
    {ok, PkiUser} = pki_serv:read(<<"foo">>),
    ok = pki_serv:update(PkiUser),
    {error, permission_denied} =
        pki_serv:update(PkiUser#pki_user{password = <<"zip">>}),
    {error, permission_denied} = pki_serv:delete(<<"foo">>, <<"zip">>),
    ok = pki_serv:delete(<<"foo">>, <<"baz">>),
    {error, no_such_user} = pki_serv:read(<<"foo">>).
