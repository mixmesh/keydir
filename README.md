# PKI server and client 

A simple Public Key Infrastructure (PKI) server as defined in https://en.wikipedia.org/wiki/Public_key_infrastructure

The PKI server can be configured using a pki configuration directive
Obscrete's configuration files as seen in ./obscrete/etc/*.conf.

## Files

<dl>
  <dt>./src/pki_app.erl</dt>
  <dd>Application module</dd>
  <dt>./src/pki_sup.erl</dt>
  <dd>Application supervisor module</dd>
  <dt>./src/pki_serv.erl</dt>
  <dd>The core PKI server without any networking</dd>
  <dt>./src/pki_network_serv.erl</dt>
  <dd>A TCP listener which marshalls incoming network requests and calls pki_serv</dd>
  <dt>./src/pki_network_client.erl</dt>
  <dd>A client library which marshalls outgoing network requests and sends them to pki_network_serv</dd>
  <dt>./src/pki_util.erl</dt>
  <dd>Common code shared by pki_network_serv and pki_network_client</dd>
  <dt>./src/pki_config_schema.erl</dt>
  <dd>The PKI server has its own section in the Obscrete config file, e.g. see ./obscrete/etc/*.conf. This schema is activated in Obscrete's application file as seen in ./obscrete/ebin/obscrete.app.</dd>
  <dt>./test/test_pki_serv.erl</dt>
  <dd>Test for the pki_serv module</dd>
  <dt>./test/test_belgamal.erl</dt>
  <dd>Test for the pki_network_serv module</dd>
</dl>

## Testing

`make runtest` runs all tests, i.e.

```
$ ../obscrete/bin/run_test --config ../obscrete/etc/obscrete-pki-only.conf test/
```

Tests can be run individually as well:

```
$ ../obscrete/bin/run_test --config ../obscrete/etc/obscrete-pki-only.conf pki_serv
$ ../obscrete/bin/run_test --config ../obscrete/etc/obscrete-pki-only.conf pki_network_serv

```
