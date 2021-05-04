-ifndef(KEYDIR_SERVICE_HRL).
-define(KEYDIR_SERVICE_HRL, true).

-include_lib("elgamal/include/elgamal.hrl").

-define(NYM_ATTRIBUTE, 128).
-define(GIVEN_NAME_ATTRIBUTE, 129).
-define(PERSONAL_NUMBER_ATTRIBUTE, 130).

-record(keydir_key,
        {key_id :: keydir_service:key_id(),
         fingerprint :: keydir_service:fingerprint(),
         user_ids = [] :: [keydir_service:user_id()],
         nym :: keydir_service:nym() | undefined,
         given_name :: bank_id:given_name() | undefined,
         personal_number :: bank_id:personal_number() | undefined,
         password :: keydir_service:password() | undefined,
         verified :: boolean() | undefined}).

-endif.
