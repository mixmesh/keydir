-ifndef(PKI_SERV_HRL).
-define(PKI_SERV_HRL, true).

-record(user, {%% string()
               name,
               %% integer()
               password,
               %% string()
               email = "",
               %% +#elgamal:pk
               public_key}).

-endif.
