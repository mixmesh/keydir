# PKI server and client 

A simple Public Key Infrastructure (PKI) server as defined in https://en.wikipedia.org/wiki/Public_key_infrastructure

The PKI server can be configured using a PKI configuration directive in
Mixmesh's configuration files as seen in ./mixmesh/etc/*.conf.

## Files

<dl>
  <dt>./src/pki_app.erl</dt>
  <dd>The simulator application module</dd>
  <dt>./src/pki_sup.erl</dt>
  <dd>The top-level supervisor</dd>
  <dt>./src/pki_serv.erl</dt>
  <dd>A core PKI server without any networking</dd>
  <dt>./src/pki_network_serv.erl</dt>
  <dd>A TCP listener which marshalls incoming network requests and calls pki_serv.erl</dd>
  <dt>./src/pki_network_client.erl</dt>
  <dd>A client library which marshalls outgoing network requests and sends them to pki_network_serv.erl</dd>
  <dt>./src/pki_util.erl</dt>
  <dd>Common code shared by pki_network_serv.erl and pki_network_client.erl</dd>
  <dt>./src/pki_config_schema.erl</dt>
  <dd>The PKI server has its own section in the Mixmesh config file, e.g. see ./mixmesh/etc/*.conf. This schema is activated in Mixmesh's application file as seen in ./mixmesh/ebin/mixmesh.app.</dd>
  <dt>./test/test_pki_serv.erl</dt>
  <dd>Test for the pki_serv module</dd>
  <dt>./test/test_belgamal.erl</dt>
  <dd>Test for the pki_network_serv module</dd>
</dl>

## Testing

`make runtest` runs all tests, i.e.

`$ ../mixmesh/bin/run_test --config ../mixmesh/etc/mixmesh-pki-only.conf test/`

Tests can be run individually as well:

```
$ ../mixmesh/bin/run_test --config ../mixmesh/etc/mixmesh-pki-only.conf pki_serv
$ ../mixmesh/bin/run_test --config ../mixmesh/etc/mixmesh-pki-only.conf pki_network_serv
```
