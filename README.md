# A Key Directory (Keydir) server and client

The Keydir server can be configured using a keydir configuration directive in
Mixmesh's configuration files as seen in ./mixmesh/etc/*.conf.

## Files

<dl>
  <dt>./src/keydir_app.erl</dt>
  <dd>The simulator application module</dd>
  <dt>./src/keydir_sup.erl</dt>
  <dd>The top-level supervisor</dd>
  <dt>./src/keydir_serv.erl</dt>
  <dd>A core Keydir server without any networking</dd>
  <dt>./src/keydir_network_serv.erl</dt>
  <dd>A TCP listener which marshalls incoming network requests and calls keydir_serv.erl</dd>
  <dt>./src/keydir_network_client.erl</dt>
  <dd>A client library which marshalls outgoing network requests and sends them to keydir_network_serv.erl</dd>
  <dt>./src/keydir_util.erl</dt>
  <dd>Common code shared by keydir_network_serv.erl and keydir_network_client.erl</dd>
  <dt>./src/keydir_config_schema.erl</dt>
  <dd>The Keydir server has its own section in the Mixmesh config file, e.g. see ./mixmesh/etc/*.conf. This schema is activated in Mixmesh's application file as seen in ./mixmesh/ebin/mixmesh.app.</dd>
  <dt>./test/test_keydir_serv.erl</dt>
  <dd>Test for the keydir_serv module</dd>
  <dt>./test/test_belgamal.erl</dt>
  <dd>Test for the keydir_network_serv module</dd>
</dl>

## Testing

`make runtest` runs all tests, i.e.

`$ ../mixmesh/bin/run_test --config ../mixmesh/etc/mixmesh-keydir-only.conf test/`

Tests can be run individually as well:

```
$ ../mixmesh/bin/run_test --config ../mixmesh/etc/mixmesh-keydir-only.conf keydir_serv
$ ../mixmesh/bin/run_test --config ../mixmesh/etc/mixmesh-keydir-only.conf keydir_network_serv
```
