# Start the keydir server

Let's try the keydir server with a number of curl examples. First
start a mixmesh instance with a keydir server running on port 4436:

```
~/src/mixmesh/mixmesh$ **./bin/mixmesh --config etc/mixmesh-keydir-only.conf**
Erlang/OTP 23 [erts-11.1] [source] [64-bit] [smp:8:8] [ds:8:8:10] [async-threads:1] [hipe]

Eshell V11.1  (abort with ^G)
(mixmesh@localhost)1> =INFO REPORT==== 11-May-2021::14:14:21.396354 ===
Copied etc/mixmesh-keydir-only.conf to etc/mixmesh-keydir-only.conf-disaster-backup
=INFO REPORT==== 11-May-2021::14:14:21.398059 ===
Config revision unchanged: 1
== DAEMON REPORT (system) ==== 11-May-2021::14:14:21.467 ====
Remote Keydir server has been started: /tmp/mixmesh/remote-keydir-server
== DAEMON REPORT (system) ==== 11-May-2021::14:14:21.470 ====
Keydir TCP server started on 0.0.0.0:11112
== DAEMON REPORT (system) ==== 11-May-2021::14:14:21.479 ====
Keydir service started on 0.0.0.0:4436
```

# Go to the keydir test directory

Start a new terminal shell and go to ~src/mixmesh/keydir/test/:

```
~$ cd ~/src/mixmesh/keydir/test
```

Inspect the pre-generated keys in the directory. They have been
generated with the mixmesh/keydir/test/mkkey script as seen in
mixmesh/keydir/test/Makefile.

Inspect them:

```
~/src/mixmesh/keydir/test$ **gpg --show-keys alice.key**
pub   rsa1024 2021-05-11 [SCEA] [expires: 2022-05-11]
      D201EF3A8E6C03D2A2A215D1D488B49E34516037
uid                      alice
sub   elg1024 2021-05-11 [E] [expires: 2022-05-11]

~/src/mixmesh/keydir/test$ **gpg --show-keys alice-bank-id.key**
pub   rsa1024 2021-05-11 [SCEA] [expires: 2022-05-11]
      84A18E52CC3C0A746B3D9DC3E4454B982871A3E4
uid                      MM-PNO:201701012393
uid                      alice
sub   elg1024 2021-05-11 [E] [expires: 2022-05-11]

~/src/mixmesh/keydir/test$ **gpg --show-keys bob.key**
pub   rsa1024 2021-05-11 [SCEA] [expires: 2022-05-11]
      B4FE98A8E4EB709B49918B68BC6FA7070AC68F84
uid                      MM-NYM:bob
sub   elg1024 2021-05-11 [E] [expires: 2022-05-11]

~/src/mixmesh/keydir/test$ **gpg --show-keys chuck.key**
pub   rsa1024 2021-05-11 [SCEA] [expires: 2022-05-11]
      EC6687F6AE35425AACADCE394C2841D16AB6328D
uid                      MM-NYM:alice
uid                      alice
uid                      bob
sub   elg1024 2021-05-11 [E] [expires: 2022-05-11]

~/src/mixmesh/keydir/test$ **gpg --show-keys fred.key**
pub   rsa1024 2021-05-11 [SCEA] [expires: 2022-05-11]
      EA96D0D2857D34A9F9BE420430555F7123EB588B
uid                      MM-NYM:fred
sub   elg1024 2021-05-11 [E] [expires: 2022-05-11]
```

**TIP**: Note the key fingerprints and User IDs. They will be used in
forthcoming curl examples.

# Lets have some fun!

## Try to read a non-existing key, i.e. using  non-existing fingerprint:

```
~/src/mixmesh/keydir/test$ **curl -k -H 'Content-Type: application/json' -X POST -d '{"fingerprint": "A88BEB308571D19F9D1C6A845658BFF76715FB9E"}' https://localhost:4436/read**
{
  "errorMessage": "No such key"
}
```

Well, it didn't exist.

## Create Bob's key

Upload bob.key to the server but first login with the fingerprint 
adhering to bob.key (see above):

```
~/src/mixmesh/keydir/test$ **curl -H "Content-Type: application/json"
 -X POST -d '{"fingerprint": "A88BEB308571D19F9D1C6A845658BFF76715FB9E", "password": "mortuta42"}' http://localhost:4436/passwordLogin**
{
  "sessionTicket": "FOOBAR"
}
```

It worked! Now upload bob.key with the help of the session ticket:

```
~/src/mixmesh/keydir/test$ **FINGERPRINT="FOOBAR"**
~/src/mixmesh/keydir/test$ **KEY=`cat bob.key`**
~/src/mixmesh/keydir/test$ **curl -H "Content-Type: application/json" -X POST -d "{\"sessionTicket\": \"FOOBAR\"}, \"key\": \"${KEY}\"" http://localhost:4436/create
```
