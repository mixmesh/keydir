-ifndef(KEYDIR_SERV_HRL).
-define(KEYDIR_SERV_HRL, true).

-include_lib("elgamal/include/elgamal.hrl").

-record(keydir_user,
        {nym :: binary(),
         password = <<>> :: binary(),
         email = <<>> :: binary(),
         public_key :: #pk{}}).

-endif.
