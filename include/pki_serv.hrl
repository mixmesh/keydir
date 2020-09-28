-ifndef(PKI_SERV_HRL).
-define(PKI_SERV_HRL, true).

-include_lib("elgamal/include/elgamal.hrl").

-record(db_user,
        {name           :: binary(),
         password       :: binary(),
         email = <<"">> :: binary(),
         public_key     :: #pk{}}).

-endif.
