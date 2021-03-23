-module(pki_webkey_service).
-export([start_link/3]).
-export([handle_http_request/4]).

-include_lib("apptools/include/log.hrl").
-include_lib("apptools/include/shorthand.hrl").
-include_lib("rester/include/rester_http.hrl").
-include_lib("elgamal/include/elgamal.hrl").
-include_lib("pki/include/pki_serv.hrl").

%% The section references below refer to
%% A: https://tools.ietf.org/pdf/draft-koch-openpgp-webkey-service-11.pdf
%% B: https://tools.ietf.org/pdf/draft-ietf-openpgp-rfc4880bis-10.pdf

%% (B) Section 5.5.1.1: Public-Key Packet (Tag 6)
-define(PGP_VERSION_4, 4).

%% (B) Section 4.2: Packets Headers
-define(OLD_PACKET_FORMAT, 2#10).

%% (B) Section 4.3: Packets Tags
-define(PUBLIC_KEY_PACKET, 6).
-define(USER_ID_PACKET, 13).

%% (B) Section 9.1: Public-Key Algorithms
-define(PUBLIC_KEY_ALGORITHM_ELGAMAL, 16).

%% Exported: start_link

start_link(Address, Port, CertFilename) ->
    ResterHttpArgs =
	[{request_handler, {?MODULE, handle_http_request, []}},
	 {verify, verify_none},
	 {ifaddr, Address},
	 {certfile, CertFilename},
	 {nodelay, true},
	 {reuseaddr, true}],
    ?daemon_log_tag_fmt(system, "PKI Webkey service started on ~s:~w",
                        [inet:ntoa(Address), Port]),
    rester_http_server:start_link(Port, ResterHttpArgs).

%% Exported: handle_http_request

handle_http_request(Socket, Request, Body, Options) ->
    ?dbg_log_fmt("request = ~s, headers=~s, body=~p",
                 [rester_http:format_request(Request),
                  rester_http:format_hdr(Request#http_request.headers),
                  Body]),
    try
        case Request#http_request.method of
            Method when Method == 'HEAD' orelse Method == 'GET' ->
                handle_http_head_and_get(Socket, Request, Body, Options);
            _ ->
                rest_util:response(Socket, Request, {error, not_allowed})
        end
    catch _Class:Reason:StackTrace ->
	    ?error_log_fmt("handle_http_request: crash reason=~p\n~p\n",
                           [Reason, StackTrace]),
	    erlang:error(Reason)
    end.

handle_http_head_and_get(Socket, Request, _Body, _Options) ->
    Url = Request#http_request.uri,
    case string:tokens(Url#url.path, "/") of
        %% (A) Section 4.5: Policy Flags
        ["WELLKNOWN", "policy"] ->
            rest_util:response(Socket, Request, {ok, ""});
        %% (A) Section 3.1: Key Discovery (advanced method)
        [".well-known", "openpgpkey", _DomainPart, "hu", _LocalPartDigest] ->
            return_key(Socket, Request, Url, Request#http_request.method);
        %% (A) Section 3.1: Key Discovery (direct method)
        [".well-known", "openpgpkey", "hu", _LocalPartDigest] ->
            return_key(Socket, Request, Url, Request#http_request.method);
        _Tokens ->
            rest_util:response(Socket, Request, {error, not_found})
    end.

return_key(Socket, Request, Url, Method) ->
    case uri_string:dissect_query(Url#url.querypart) of
        [{"l", LocalPart}] ->
            case pki_serv:read(?l2b(LocalPart))  of
                {ok, PkiUser} ->
                    PgpMessage = pgp_message(PkiUser),
                    response(Socket, Request, 200, "OK", PgpMessage,
                             [{content_type, "application/octet-stream"}], Method);
                {error, _Reason} ->
                    rest_util:response(Socket, Request, {error, not_found})
            end;
        _ ->
            response(Socket, Request, 400, "Bad Request",
                     "Invalid query string", [], Method)
    end.

response(Socket, Request, Status, Phrase, Body, Opts, 'HEAD') ->
    response(Socket, Request, Status, Phrase, {skip_body, Body}, Opts, 'GET');
response(Socket, Request, Status, Phrase, Body, Opts, _Method) ->
    rester_http_server:response_r(Socket, Request, Status, Phrase, Body, Opts).

pgp_message(#pki_user{nym = Nym, public_key = PublicKey}) ->
    UserIdPacket = add_packet_header(?USER_ID_PACKET, user_id_packet(Nym)),
    PublicKeyPacket =
        add_packet_header(?PUBLIC_KEY_PACKET, public_key_packet(PublicKey)),
    <<UserIdPacket/binary, PublicKeyPacket/binary>>.

user_id_packet(Nym) ->
    <<?USER_ID_PACKET, Nym/binary>>.

%% (B) Section 4.2.1: Old Format Packet Lengths
add_packet_header(Tag, Packet) ->
    {LenBits, Length} =
        case byte_size(Packet) of
            S when S < 16#100 ->
                {0, <<S>>};
            M when M < 16#10000 ->
                {1, <<M:16>>};
            L when L < 16#100000000 ->
                {2, <<L:32>>}
        end,
    <<?OLD_PACKET_FORMAT:2, Tag:4, LenBits:2, Length/binary, Packet/binary>>.

%% (B) Section 5.5.1.1: Public-Key Packet (Tag 6)
public_key_packet(#pk{h = H}) ->
    Timestamp = erlang:system_time(seconds),
    %% (B) Section 5.6.3: Algorithm-Specific Part for Elgamal Keys
    %% Multiprecision integers: H = G ** K mod P.
    PBin = binary:encode_unsigned(?P),
    PBinSize = byte_size(PBin),
    GBin = binary:encode_unsigned(?G),
    GBinSize = byte_size(GBin),
    HBin = binary:encode_unsigned(H),
    HBinSize = byte_size(HBin),
    <<?PGP_VERSION_4,
      Timestamp:32,
      ?PUBLIC_KEY_ALGORITHM_ELGAMAL,
      PBinSize:16, PBin/binary,
      GBinSize:16, GBin/binary,
      HBinSize:16, HBin/binary>>.
