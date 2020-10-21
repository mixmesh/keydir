-module(pki_util).
-export([read_integer/3, read_binary/3, read_user/2]).
-export([write_integer/3, write_binary/3, write_user/2]).

-include("../include/pki_serv.hrl").

%% Exported: read_integer

read_integer(Length, Transport, Timeout) ->
    case pki_network_client:recv(Transport, Length, Timeout) of
        {ok, <<Integer:Length/unsigned-integer-unit:8>>} ->
            Integer;
        {error, Reason} ->
            throw({?MODULE, {recv_error, Reason}})
    end.

%% Exported: read_binary

read_binary(Length, Transport, Timeout) ->
    case read_integer(Length, Transport, Timeout) of
        0 ->
            <<>>;
        Size ->
            case pki_network_client:recv(Transport, Size, Timeout) of
                {ok, Binary} ->
                    Binary;
                {error, Reason} ->
                    throw({?MODULE, {recv_error, Reason}})
            end
    end.

%% Exported: read_user

read_user(Transport, Timeout) ->
    Nym = read_binary(1, Transport, Timeout),
    Password = read_binary(1, Transport, Timeout),
    Email = read_binary(1, Transport, Timeout),
    PublicKey = read_binary(2, Transport, Timeout),
    #pki_user{nym = Nym,
              password = Password,
              email = Email,
              public_key = elgamal:binary_to_public_key(PublicKey)}.

%% Exported: write_integer

write_integer(Length, Transport, Integer) ->
    case pki_network_client:send(
           Transport, <<Integer:Length/unsigned-integer-unit:8>>) of
        ok ->
            ok;
        {error, Reason} ->
            throw({?MODULE, {tcp_send_error, Reason}})
    end.

%% Exported: write_binary

write_binary(Length, Transport, Binary) ->
  Size = size(Binary),
  ok = write_integer(Length, Transport, Size),
  case Size of
      0 ->
          ok;
      _ ->
          case pki_network_client:send(Transport, Binary) of
              ok ->
                  ok;
              {error, Reason} ->
                  throw({?MODULE, {tcp_send_error, Reason}})
          end
  end.

%% Exported: write_user

write_user(Transport, #pki_user{nym = Nym,
                                password = Password,
                                email = Email,
                                public_key = PublicKey}) ->
    ok = write_binary(1, Transport, Nym),
    ok = write_binary(1, Transport, Password),
    ok = write_binary(1, Transport, Email),
    write_binary(2, Transport, elgamal:public_key_to_binary(PublicKey)).
