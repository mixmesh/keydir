# A Key Directory (Keydir) server and client

The Keydir server can be configured using a keydir configuration directive in
Mixmesh's configuration files as seen in ./mixmesh/etc/*.conf.

## Create release using servator

When creating a release using servator, for simplictity, set the directory to the one of mixmesh. Then start keydir using the standard script.

	$ cd mixmesh
	$ ./bin/mixmesh --config ./etc/mixmesh-keydir-only.conf
	
Make sure all applications are started, that are required to run for normla operation of keydir service, including new applications added. Forexample there may be a need to update mixmesh.erl for the application to start properly.

Now make sure servator is in the erlang path, and issue the command, given that 1.0.1 is the current release tag.

	> servator:make_release(keydir, "1.0.1")
	
This will create a release directory under keydir-1.0.1

### install 

To install that release (copy it) cd to keydir-1.0.1 and run ./install.sh
this will create the nessesary structure needed to run the application under

	/etc/erlang/keydir
	
and

	/var/erlang/keydir
	

## Start node

The node started is currently called mixmesh@localhost, must be fixed,
A change in bin/mixmesh script is needed for that.

To start the node run
	
	/etc/erlang/keydir/keydir.run start

There are various ways of starting servator generated releases, see README
in servator.

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

