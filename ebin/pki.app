%% -*- erlang -*-
{application, pki,
 [{description, "PKI server and client"},
  {vsn, "1.0"},
  {modules, [pki_app,
             pki_config_schema,
             pki_network_client,
             pki_network_serv,
             pki_serv,
             pki_sup,
             pki_util]},
  {registered, [pki_serv, pki_sup]},
  {mod, {pki_app, []}},
  {applications, [kernel, stdlib]}]}.
