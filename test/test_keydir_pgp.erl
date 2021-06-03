-module(test_keydir_pgp).
-export([start/0]).

-include_lib("elgamal/include/elgamal.hrl").

start() ->
    Pk = #pk{nym = <<"alice">>,
             h = 992386128104556632067706199376325953656672084355200892860068491430799817128578784087759225810836516281141924658846714169564988944342566325878527874045727193805699080422366318323603659262419704791415825613732484456825567597291115960962349816896231473561170880759418646262741970485908875445925631603167519100354},
    io:format("Pk = ~p\n", [Pk]),
    {ok, Fingerprint, PgpKey} = keydir_pgp:pk_to_key(Pk),
    io:format("Fingerprint = ~p\n", [Fingerprint]),
    io:format("PgpKey = ~p\n", [PgpKey]),
    {ok, Pk} = keydir_pgp:key_to_pk(PgpKey).
