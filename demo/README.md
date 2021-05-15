# The keydir service

The keydir service is a persistent storage service which provides a
REST API over HTTP/S and exports a CRUD API to manage PGP keys. This
is indeed not a new thing and both "The OpenPGP HTTP Keyserver
Protocol (HKP)" [1], https://keys.openpgp.org and
https://hockeypuck.io comes to mind.

The keydir service has Bank ID authentication support built in though
and it is obviously a better solution than all the competition put
together. :-)

Follow the instructions below for a curl driven demo of its
functionality.

[1] https://datatracker.ietf.org/doc/html/draft-shaw-openpgp-hkp-00

# Introduction to the demo

Lets try the keydir service with a number of curl examples. First
start a Mixmesh instance with a keydir service running on port 4436: 

```
$ cd ~/src/mixmesh/mixmesh
$ ./bin/mixmesh --config etc/mixmesh-keydir-only.conf
```

# Go to the keydir service demo directory

Start a new terminal shell and go to ~src/mixmesh/keydir/demo:

```
$ cd ~/src/mixmesh/keydir/demo
```

Inspect the pre-generated demo keys:

```
$ gpg --show-keys alice-bank-id.key 
pub   rsa1024 2021-05-14 [SCEA] [expires: 2022-05-14]
      3E00ACEE4AF601B42547243335B51ACAC65404B0
uid                      MM-PNO:201701012393
uid                      alice
sub   elg1024 2021-05-14 [E] [expires: 2022-05-14]

$ gpg --show-keys bob.key
pub   rsa1024 2021-05-14 [SCEA] [expires: 2022-05-14]
      7B6F0127661B993D584F7875F3B5DF1462C00D87
uid                      MM-NYM:bob
sub   elg1024 2021-05-14 [E] [expires: 2022-05-14]

$ gpg --show-keys chuck.key
pub   rsa1024 2021-05-14 [SCEA] [expires: 2022-05-14]
      35E130DD43043ADC658273019F50A63B44B6A10C
uid                      MM-NYM:alice
uid                      bob
uid                      alice
sub   elg1024 2021-05-14 [E] [expires: 2022-05-14]
```

**NOTE**: The gpg --show-keys option lists the User IDs in reverse
 order compared to the actual pgp packet ordering. This means that the
 primary User ID for alice-bank-id.key is "alice" (nothing else). If 
 in doubt check with gpg --list-packets.

**TIP**: Note the key fingerprints and User IDs above. They will be
  used in forthcoming curl examples.

Understand the following:

* alice-bank-id.key has two User IDs, i.e. "alice" is the unadorned
  primary User ID and "MM-PNO:20170101239" identifies the Mixmesh
  Personal Number. The personal number is mandatory for a key which is
  to be created on the keydir service using Bank ID
  authentication. The primary User ID also functions as the Mixmesh
  Nym.

* bob.key has two User IDs, i.e. "bob" is the unadorned primary User
  ID and "MM-NYM:bob" identifies the Mixmesh Nym (both are the same
  for this key).

* chuck.key is a tricky bastard and has three ambiguous User
  IDs. "alice" is the unadorned primary User ID and "bob" is an extra
  User ID. "MM-PNO:bob" identifies the Mixmesh Nym. This is all very
  confusing and done out of spite. It is perfectly OK for Chuck to be
  this devious.

There is actually one more adorned Mixmesh User ID that is not used in
the keys above and it is "MM-GN: *" (Given Name). It works in concert
with "MM-PNO: *" to aid the Bank ID authentication. To be more
precise: A "MM-PNO: *" User ID **must** exist and **must** exactly
match the user's Personal Number negotiated during Bank ID
authentication. A "MM-GN: *" User ID **may** exist and if it does it
**must** exactly match the Given Name negotiated during the Bank ID
authentication.

**NOTE**: Chuck's confusing list of User IDs are introduced to show
that the only User ID that ever can be considered unique is "MM-PNO:
*" negotiated during Bank ID authentication.

# Lets have some fun!

In all the calls to curl below a common curlrc file is used. It looks
like this: 

```
$ cat curlrc
-H "Content-Type: application/json"
-X POST
```

The keydir service REST API exports the following request URIs:

* /passwordLogin - Login using password authetication
* /bankIdAuth - Initialize a Bank ID authentication
* /bankIdCollect - Wait for a Bank ID app to authenticate a key to be managed
* /logout - Logout from a password login or a Bank ID authentication
* /create - Create a new key (must **not** exist)
* /read - Read a key using various criteria
* /update - Update an existing key or create a new key
* /delete - Delete a key
* /pks/lookup - Perform a HKP lookup operation
* /pks/add - Perform a HKP add operation

The HKP acronym refers to the "The OpenPGP HTTP Keyserver Protocol
(HKP)" [1] and to information provided in
https://keys.openpgp.org/about/api.

[1] https://datatracker.ietf.org/doc/html/draft-shaw-openpgp-hkp-00 and

## Try to read a non-existing key

Use the bogus fingerprint "FEEDBABEFF" to read a non-existing key:

```
$ curl -K curlrc -d '{"fingerprint": "FEEDBABEFF"}' http://localhost:4436/read
{
  "errorMessage": "No such key"
}
```

Well, it did not exist.

## Login with the fingerprint associated with bob.key

Login to the keydir service with the fingerprint associated with bob.key
(see above) and a nice password. 

**NOTE**: Do not be hasty. The alice-bank-id.key will be used in due
  time to perform Bank ID authentication as well.

```
$ BODY='{"fingerprint": "7B6F0127661B993D584F7875F3B5DF1462C00D87", "password": "mortuta42"}'
$ curl -K curlrc -d "${BODY}" http://localhost:4436/passwordLogin
{
  "sessionTicket": "zy2ZmY02KUaKeJp0fX8NJdPg1RwTanxrO9IqZRaDgFo="
}
```

It worked!

Lets save the session ticket in an environment variable so it can be
used later on:

```
$ BOB_TICKET="zy2ZmY02KUaKeJp0fX8NJdPg1RwTanxrO9IqZRaDgFo="
```

All examples below store session tickets in variables for future use.

## Try to create chuck.key with the bob.key session ticket

Try to use the bob.key session ticket to create chuck.key. This will
fail:

```
$ KEY=`cat chuck.key`
$ BODY="{\"sessionTicket\": \"${BOB_TICKET}\", \"key\": \"${KEY}\"}"
$ curl -K curlrc -d "${BODY//$'\n'/\\n}" http://localhost:4436/create
{
  "errorMessage": "Fingerprint does not match login credentials"
}
```

That was indeed expected!

## Create bob.key

Use the bob.key session ticket to create bob.key:

```
$ KEY=`cat bob.key`
$ BODY="{\"sessionTicket\": \"${BOB_TICKET}\", \"key\": \"${KEY}\"}"
$ curl -K curlrc -d "${BODY//$'\n'/\\n}" http://localhost:4436/create
```

No news is good news!

## Login with the fingerprint associated with chuck.key

Login to the keydir service with the fingerprint associated with
chuck.key (see above) and a nice password. 

```
$ BODY='{"fingerprint": "35E130DD43043ADC658273019F50A63B44B6A10C", "password": "mortuta42"}'
$ curl -K curlrc -d "${BODY}" http://localhost:4436/passwordLogin
{
  "sessionTicket": "WSCX3lYwESQ/wcWQLC8agP7m1MK571ba6ugcu/0ORHg="
}
$ CHUCK_TICKET="WSCX3lYwESQ/wcWQLC8agP7m1MK571ba6ugcu/0ORHg="
```

It worked!

## Create chuck.key

Use the chuck.key session ticket to create chuck.key:

```
$ KEY=`cat chuck.key`
$ BODY="{\"sessionTicket\": \"${CHUCK_TICKET}\", \"key\": \"${KEY}\"}"
$ curl -K curlrc -d "${BODY//$'\n'/\\n}" http://localhost:4436/create
```

No news is good news!

Only non-existing keys can be created:

```
$ curl -K curlrc -d "${BODY//$'\n'/\\n}" http://localhost:4436/create
{
  "errorMessage": "Key already exists"
}
```

The "update" request URI must be used to modify already existing keys.

## Logout with the fingerprint associated with bob.key

Use the bob.key session ticket to logout from the keydir service:

```
$ BODY="{\"sessionTicket\": \"${BOB_TICKET}\"}"
$ curl -K curlrc -d "${BODY}" http://localhost:4436/logout
```

No news is good news!

Just to be sure. Try to logout again:

```
$ curl -K curlrc -d "${BODY}" http://localhost:4436/logout
}
  "errorMessage": "No such session"
}
```

That was not a surprise!

## Login using Bank ID authentication

Login to the keydir service with the fingerprint associated with
alice-bank-id.key (see above) using Bank ID authentication. Do this
with a single request to http://localhost:4436/bankIdAuth followed by
continous requests to http://localhost:4436/bankIdCollect during at
most two minutes and with a two seconds interval between each request.

For this to succeed the Personal Number specified in the request to
http://localhost:4436/bankIdAuth **must** match the Personal Number
negotiated during the Bank ID authentication.

```
$ curl -K curlrc -d '{"fingerprint": "3E00ACEE4AF601B42547243335B51ACAC65404B0", "personalNumber": "201701012393"}' http://localhost:4436/bankIdAuth
{
  "sessionTicket": "SY5ht5B/KCfhgWac5p/CoxguGwidqKcTBZMUM2VbILU="
}
$ ALICE_TICKET = "SY5ht5B/KCfhgWac5p/CoxguGwidqKcTBZMUM2VbILU="
```

The session ticket can now be used to continously request
http://localhost:4436/bankIdCollect until Bank ID negotiation succeeds
or fails. In this demo a small shell script is used to do the
collecting. You can obviously do this manually if you are a really
fast typer. :-) 

```
$ ./bankidcollect ${ALICE_TICKET}

Calling: curl -s -K curlrc -d '{"sessionTicket": "SY5ht5B/KCfhgWac5p/CoxguGwidqKcTBZMUM2VbILU="}' http://localhost:4436/bankIdCollect
{
  "hintCode": "outstandingTransaction",
  "status": "pending"
}

Calling: curl -s -K curlrc -d '{"sessionTicket": "SY5ht5B/KCfhgWac5p/CoxguGwidqKcTBZMUM2VbILU="}' http://localhost:4436/bankIdCollect
{
  "hintCode": "outstandingTransaction",
  "status": "pending"
}

...

Calling: curl -s -K curlrc -d '{"sessionTicket": "SY5ht5B/KCfhgWac5p/CoxguGwidqKcTBZMUM2VbILU="}' http://localhost:4436/bankIdCollect
{
  "hintCode": "noClient",
  "status": "pending"
}

Calling: curl -s -K curlrc -d '{"sessionTicket": "SY5ht5B/KCfhgWac5p/CoxguGwidqKcTBZMUM2VbILU="}' http://localhost:4436/bankIdCollect
{
  "hintCode": "noClient",
  "status": "pending"
}

...

Calling: curl -s -K curlrc -d '{"sessionTicket": "SY5ht5B/KCfhgWac5p/CoxguGwidqKcTBZMUM2VbILU="}' http://localhost:4436/bankIdCollect
Abort: {
  "hintCode": "expiredTransaction",
  "status": "failed"
}
```

Oh no! It failed after two minutes. This happens if no Bank ID app was
started at all.

Lets start the Bank ID app and try again:

```
$ curl -K curlrc -d '{"fingerprint": "3E00ACEE4AF601B42547243335B51ACAC65404B0", "personalNumber": "201701012393"}' http://localhost:4436/bankIdAuth
{
  "sessionTicket": "UjoHrrwWnZtspLd8Atv2zTujKp59U34EPYUb+UyWpBI="
}
$ ALICE_TICKET = "UjoHrrwWnZtspLd8Atv2zTujKp59U34EPYUb+UyWpBI="
```

Followed by:

```
$ ./bankidcollect ${ALICE_TICKET}
Calling: curl -s -K curlrc -d '{"sessionTicket": "UjoHrrwWnZtspLd8Atv2zTujKp59U34EPYUb+UyWpBI="}' http://localhost:4436/bankIdCollect
{
  "hintCode": "userSign",
  "status": "pending"
}

...

Calling: curl -s -K curlrc -d '{"sessionTicket": "UjoHrrwWnZtspLd8Atv2zTujKp59U34EPYUb+UyWpBI="}' http://localhost:4436/bankIdCollect
{
  "status": "complete"
}
```

It is done! The Bank ID authentication succeeded and the session
ticket can now be used to perform operations on alice-bank-id.key.

## Create alice-bank-id.key

Use the alice-bank-id.key session ticket to create alice-bank-id.key:

```
$ KEY=`cat alice-bank-id.key`
$ BODY="{\"sessionTicket\": \"${ALICE_TICKET}\", \"key\": \"${KEY}\"}"
$ curl -K curlrc -d "${BODY//$'\n'/\\n}" http://localhost:4436/create
```

No news is good news!

## Read bob.key using its fingerprint 

A fingerprint uniquely identifies a key:

```
$ BODY='{"fingerprint": "7B6F0127661B993D584F7875F3B5DF1462C00D87"}'
$ curl -K curlrc -d "${BODY}" http://localhost:4436/read
----BEGIN PGP PUBLIC KEY BLOCK-----
mI0EYJv2FAEEAMuxgKZPxFh3//vqXUGVGJ1ZbmUP0BanOBppUY8Hy6fNfp2F61sv
gUUc/l3xg9bdoPlNfiz+HqDc6GC+QWT7jWpcUNOufpCwT3aq6Mq0KXlLqCk6LnfO
0nZZHVbHINCUsjKsnCSpCg1MQGJDJBir/t2MA0cS0YMOepn6TQn9o81NABEBAAG0
BWFsaWNliNQEEwEKAD4WIQQQJcdKhGDk6wnejE3DmnxL54nZZgUCYJv2FAIbLwUJ
AeEzgAULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRDDmnxL54nZZuDEA/49EZTF
fAs7xzTWABGb5oX5xo8EpiRrmIZl2G6deGhJkG55lLN2RfkHPArfRx1VRxb6QKwY
Z4nf8wz48eZ/4TfmaaOh/DlGj4RIlJXmRlqombDC4qqgguf8JnA8FMu2321GKpi5
MNDQT3vOREKRzYvFtUpJqI6eNcCMo0djjH2p2rkBDQRgm/YUEAQAiVQLpHg5GzGW
DDh2RKrw2oSCDNRWvi/bY4JgQ7kG6nZ1DYzj9tb0/kXACmAQKvozSJuclej8Qb+8
LU/e9Bc/Gj8Y2M/bnbpwODhv/DimQCwpsKXIapgmx1p9Ui/x7i8fMLFhYMXrXmKH
1qnoTCSDfdnfnU/n1fnC7IhzgUAb4d8AAwUD/09PpLJiv7OEJstfeg+78Z7+jKJo
RLXm/YmO7sbKqZr8I4P9/NK3lXKGIVB7JNYR3AvpZhpNfHkk7Q061bET1H6uhy5I
G7EVJWk+6mdml/T10GY5WGSEFu68u/wTdMdfIxPODdV6KVAIZnmTaZ1jZd3ospL2
6m98inLSCWBlDq4niLwEGAEKACYWIQQQJcdKhGDk6wnejE3DmnxL54nZZgUCYJv2
FAIbDAUJAeEzgAAKCRDDmnxL54nZZtjlA/9Sc3skUcj08kU2+8tIl3bydPu62Fh9
hxPjatrgxFu4VP4H40xHCCSph04JAEH32qCQKKJMXgF2heF773m6BsEjQtrsoCwP
4xDKqWc1hJSpGDKt4nZkzXL3dMNCkdRty3o6Czdc8sOk5+lg3cUxrZXf6LIslr97
Ac8qxj43mO0HjQ==
=GFxo
-----END PGP PUBLIC KEY BLOCK-----
```

Using a bogus fingerprint results in an error message:

```
$ BODY='{"fingerprint": "FEEDBABEFF"}'
$ curl -K curlrc -d "${BODY}" http://localhost:4436/read
{
  "errorMessage": "No such key"
}
```

## Read keys matching a specific User ID

Read keys which matches a specific User ID. Zero, one or many keys may
be returned:

```
$ BODY='{"userId": "alice"}'
$ curl -K curlrc -d "${BODY}" http://localhost:4436/read
{
  "keys": [
    {
      "fingerprint": "3E00ACEE4AF601B42547243335B51ACAC65404B0",
      "keyId": "3E00ACEE4AF601B4",
      "nym": "alice",
      "personalNumber": "201701012393",
      "userIds": [
        "alice"
      ],
      "verified": true
    },
    {
      "fingerprint": "35E130DD43043ADC658273019F50A63B44B6A10C",
      "keyId": "35E130DD43043ADC",
      "nym": "alice",
      "userIds": [
        "bob",
        "alice"
      ],
      "verified": false
    }
  ]
}
```

Chuck is a shifty bastard.

## Read keys matching a specific Mixmesh Nym

Read keys which matches a specific Mixmesh Nym. Zero, one or many keys
may be returned:

```
$ BODY='{"nym": "alice"}'
$ curl -K curlrc -d "${BODY}" http://localhost:4436/read
{
  "keys": [
    {
      "fingerprint": "3E00ACEE4AF601B42547243335B51ACAC65404B0",
      "keyId": "3E00ACEE4AF601B4",
      "nym": "alice",
      "personalNumber": "201701012393",
      "userIds": [
        "alice"
      ],
      "verified": true
    },
    {
      "fingerprint": "35E130DD43043ADC658273019F50A63B44B6A10C",
      "keyId": "35E130DD43043ADC",
      "nym": "alice",
      "userIds": [
        "bob",
        "alice"
      ],
      "verified": false
    }
  ]
}
```

Chuck is **indeed** a shifty bastard.

Only one key has "bob" as its Mixmesh Nym though:

```
$ BODY='{"nym": "bob"}'
$ curl -K curlrc -d "${BODY}" http://localhost:4436/read
-----BEGIN PGP PUBLIC KEY BLOCK-----
mI0EYJ5nWQEEAKQTD0d+QR6buEvm+BWO0GV29CRtPSYIbc6Th8weVAZ+x+kNzDk7
BxwMKqRagysF71BXw5U7IEvwuwt+HVP9cZm3yMUGv9jwXu4+iHfhYWH68mDcTw0R
UreQEQj2tpoOau0/3CRpsIao4jjyk4gwX3HmzzYflSOqZsZrSf94BCc7ABEBAAG0
Ck1NLU5ZTTpib2KI1AQTAQoAPhYhBHtvASdmG5k9WE94dfO13xRiwA2HBQJgnmdZ
AhsvBQkB4TOABQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEPO13xRiwA2HmeUD
/02NQXrLZLQJPQxoLoyhf+Xj1R7j4b9gQrkEkqBYuWMEsMAt8Fu2u16w90fo2zP1
gje170zBAxrZecCoUei3GcvFEy7rqqKmWzfwPudHrCQXgQNld6vyu/LROD6dE8Jj
HD8C78Mg4jxEPLY5KAztKsMCztiwP/Fwca/I+m0gBBeXuQENBGCeZ1kQBAC2nE0+
C1qAshMoeAzQeXtQptgS25nKlWY8l4uARgI9V7xab7rVZI9BSi6MOJWCASBJhNkx
+0jk1eUSweEU+wrXkOMgO64SzmjP5Q84RzTdjtKFZAVZkCUagdE9WSqTSfkEPOOQ
orTKUlU6nPdS2R5SCQBu0V6pHu+wUJeUNiplQwADBQP/boypkxoFJqD2tJZkfTGC
3kZMIPILqEH4lS2B7E7HSgRfpi1GcVZqH5ZfYQMpQvGGuJmjxt1eUK9vot+WJ8fm
p/p63lX5kTeKLC89KXXkv5nahYs/aWTbwwrawbehW6IbaJUctiEPYWI1ZhMUKvMr
eLc02CEq58XJ+FzeWye4FxqIvAQYAQoAJhYhBHtvASdmG5k9WE94dfO13xRiwA2H
BQJgnmdZAhsMBQkB4TOAAAoJEPO13xRiwA2Hs3YEAIxjPR6JVWPZvHgXIMsFbFt6
UzMi7jMLEpxOZjDhGpPDgtf5jTbf5oItwb4VnVOzpxjQBKIWzx4+0dvNZY+138Wd
A0/1ThjTGic6ES+UOM4UJEBGfinDVRZIwcfXU+6wgpZ60AzFvl14YlFGxZaz0fsP
G6Zza1YxGjSXZ3PRkrqF
=ck9n
-----END PGP PUBLIC KEY BLOCK-----
```

**NOTE**: When only one key matches the key itself is returned.

## Read Bank ID authenticated keys matching a specific Mixmesh Nym

Read keys which matches a specific Mixmesh Nym and is verified with
Bank ID authentication. Zero, one or many keys may be returned:

```
$ BODY='{"nym": "alice", "verified": true}'
$ curl -K curlrc -d "${BODY}" http://localhost:4436/read
-----BEGIN PGP PUBLIC KEY BLOCK-----
mI0EYJ6eagEEALmvkfxRMMXfnyjskb5vD5Y/n8uiEbuEKzFKqV4xEWuBjBRHBk9T
z19e1Hhm012mFNAZlJvoTavV8Gxg1cPtxoCdHeP7IlGd4WTzu4y/6EVe8E6hDHoD
gyG5Qp+/DlsppVc2hFRfZoryfAhQO0O4Zp3une0aKvC99CbHdK3NRz45ABEBAAG0
BWFsaWNliNQEEwEKAD4WIQQ+AKzuSvYBtCVHJDM1tRrKxlQEsAUCYJ6eagIbLwUJ
AeEzgAULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRA1tRrKxlQEsCcMBACD4POx
zBK5/ecW+/gRj/T1kp2mlZ0aKSPjUJgpwknpYEp+bGl57d/cG+0HAPFuwqS69BBb
2/Viy7ldclMtzoriaQjvEPkJ3XWl1taXa5fyYu3NdsNmhx9CaNxdw5WwkDWp/hUM
Frc3gl/oGjc8AwS9IxUDVGhOYCzpms4cj0ditrQTTU0tUE5POjIwMTcwMTAxMjM5
M4jUBBMBCgA+FiEEPgCs7kr2AbQlRyQzNbUaysZUBLAFAmCenmoCGy8FCQHhM4AF
CwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQNbUaysZUBLBsAQP+IXHbb83qzqVd
qossI/HtY8XL9iuFuGah/NKD6OfFEvW1XOoKRgupiiXEG14ETzI1WaQIecaftW+u
8222YcNVJTSnzD/zixSIIqp3Qhu4lE1g2J/RA7/xJcexr/HFFKb1+Si70fzvpr8V
niIyW/chI+cvJkxevhfmNW8S3L90s+y5AQ0EYJ6eahAEAPIE6Jll1BLoqgxff43N
bztEuH4WAaM6Zq5N9qHKq4gIhTwY0GjGHxzm2XO642LAIayOqp3UuU0Lf1WOcalZ
cv1GEoF44otmFy0MxTTDlJZvT5DjGu9qAhUEqrnbOuiTVSSg2++ab5auaPvZQxE+
8faso3P5axRlwrFyJdy8KliPAAQLA/94FTmaNZbQPHGtSC16sIBNSg19rDVR58y0
ut/8kCh8JlDCayJTYgC6syiwYh3m1dTUVlGZ4E00WYJvhUgyO5RSk5NvsxExByYI
siLLQt4oDsqi9LLvcl1/asuClhdJaIUYv/bZfW4kF3TC7PMK7oijj28X/dqra07E
ior2jsTAmYi8BBgBCgAmFiEEPgCs7kr2AbQlRyQzNbUaysZUBLAFAmCenmoCGwwF
CQHhM4AACgkQNbUaysZUBLBxxQP+N+JNO9RBXKqhH4lCpD+xXL/SS6fvmAinGQaY
aG24MU6JjL7QCh4vDihQCfLOCVRF8nxPoPqfDbw4uU5pjvqHt6PUKpgB5DZiKAUm
/bvUk063Fuvgne4cxlEOfYENFS9E2heMMHht0F224rPUgdaqN42vKSEfL7eonkaN
FlpyVL0=
=Y47P
-----END PGP PUBLIC KEY BLOCK-----
```

Yes! Chuck the bastard was filtered out.

## Read keys with a number of matching filter criteria

Read keys which matches a number of criteria. Zero, one or many keys
may be returned: 

```
BODY='{"keyId": "3E00ACEE4AF601B4", "userId": "alice", "nym": "alice", "givenName": "Joe", "personalNumber": "201701012393", "verified": true}'
$ curl -K curlrc -d "${BODY}" http://localhost:4436/read
-----BEGIN PGP PUBLIC KEY BLOCK-----

mI0EYJ6eagEEALmvkfxRMMXfnyjskb5vD5Y/n8uiEbuEKzFKqV4xEWuBjBRHBk9T
z19e1Hhm012mFNAZlJvoTavV8Gxg1cPtxoCdHeP7IlGd4WTzu4y/6EVe8E6hDHoD
gyG5Qp+/DlsppVc2hFRfZoryfAhQO0O4Zp3une0aKvC99CbHdK3NRz45ABEBAAG0
BWFsaWNliNQEEwEKAD4WIQQ+AKzuSvYBtCVHJDM1tRrKxlQEsAUCYJ6eagIbLwUJ
AeEzgAULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRA1tRrKxlQEsCcMBACD4POx
zBK5/ecW+/gRj/T1kp2mlZ0aKSPjUJgpwknpYEp+bGl57d/cG+0HAPFuwqS69BBb
2/Viy7ldclMtzoriaQjvEPkJ3XWl1taXa5fyYu3NdsNmhx9CaNxdw5WwkDWp/hUM
Frc3gl/oGjc8AwS9IxUDVGhOYCzpms4cj0ditrQTTU0tUE5POjIwMTcwMTAxMjM5
M4jUBBMBCgA+FiEEPgCs7kr2AbQlRyQzNbUaysZUBLAFAmCenmoCGy8FCQHhM4AF
CwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQNbUaysZUBLBsAQP+IXHbb83qzqVd
qossI/HtY8XL9iuFuGah/NKD6OfFEvW1XOoKRgupiiXEG14ETzI1WaQIecaftW+u
8222YcNVJTSnzD/zixSIIqp3Qhu4lE1g2J/RA7/xJcexr/HFFKb1+Si70fzvpr8V
niIyW/chI+cvJkxevhfmNW8S3L90s+y5AQ0EYJ6eahAEAPIE6Jll1BLoqgxff43N
bztEuH4WAaM6Zq5N9qHKq4gIhTwY0GjGHxzm2XO642LAIayOqp3UuU0Lf1WOcalZ
cv1GEoF44otmFy0MxTTDlJZvT5DjGu9qAhUEqrnbOuiTVSSg2++ab5auaPvZQxE+
8faso3P5axRlwrFyJdy8KliPAAQLA/94FTmaNZbQPHGtSC16sIBNSg19rDVR58y0
ut/8kCh8JlDCayJTYgC6syiwYh3m1dTUVlGZ4E00WYJvhUgyO5RSk5NvsxExByYI
siLLQt4oDsqi9LLvcl1/asuClhdJaIUYv/bZfW4kF3TC7PMK7oijj28X/dqra07E
ior2jsTAmYi8BBgBCgAmFiEEPgCs7kr2AbQlRyQzNbUaysZUBLAFAmCenmoCGwwF
CQHhM4AACgkQNbUaysZUBLBxxQP+N+JNO9RBXKqhH4lCpD+xXL/SS6fvmAinGQaY
aG24MU6JjL7QCh4vDihQCfLOCVRF8nxPoPqfDbw4uU5pjvqHt6PUKpgB5DZiKAUm
/bvUk063Fuvgne4cxlEOfYENFS9E2heMMHht0F224rPUgdaqN42vKSEfL7eonkaN
FlpyVL0=
=Y47P
-----END PGP PUBLIC KEY BLOCK-----
```

It was silly to specify all possible filter criteria because the Key
ID itself was enough to pinpoint a unique key. You get the gist
though.

## Delete chuck.key

Use the chuck.key session ticket to delete chuck.key:

```
$ BODY="{\"sessionTicket\": \"${CHUCK_TICKET}\", \"fingerprint\": \"35E130DD43043ADC658273019F50A63B44B6A10C\"}"
$ curl -K curlrc -d "${BODY}" http://localhost:4436/delete
```

No news is good news!

Try again:

```
$ curl -K curlrc -d "${BODY}" http://localhost:4436/delete
{
  "errorMessage": "No such key"
}
```

QED

## Perform a HKP pks/lookup operation

Read alice-bank-id.key with a HKP lookup *get* operation:

```
$ curl "http://127.0.0.1:4436/pks/lookup?op=get&search=0x3E00ACEE4AF601B4" | lookup.key
-----BEGIN PGP PUBLIC KEY BLOCK-----
mI0EYJ6eagEEALmvkfxRMMXfnyjskb5vD5Y/n8uiEbuEKzFKqV4xEWuBjBRHBk9T
z19e1Hhm012mFNAZlJvoTavV8Gxg1cPtxoCdHeP7IlGd4WTzu4y/6EVe8E6hDHoD
gyG5Qp+/DlsppVc2hFRfZoryfAhQO0O4Zp3une0aKvC99CbHdK3NRz45ABEBAAG0
BWFsaWNliNQEEwEKAD4WIQQ+AKzuSvYBtCVHJDM1tRrKxlQEsAUCYJ6eagIbLwUJ
AeEzgAULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRA1tRrKxlQEsCcMBACD4POx
zBK5/ecW+/gRj/T1kp2mlZ0aKSPjUJgpwknpYEp+bGl57d/cG+0HAPFuwqS69BBb
2/Viy7ldclMtzoriaQjvEPkJ3XWl1taXa5fyYu3NdsNmhx9CaNxdw5WwkDWp/hUM
Frc3gl/oGjc8AwS9IxUDVGhOYCzpms4cj0ditrQTTU0tUE5POjIwMTcwMTAxMjM5
M4jUBBMBCgA+FiEEPgCs7kr2AbQlRyQzNbUaysZUBLAFAmCenmoCGy8FCQHhM4AF
CwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQNbUaysZUBLBsAQP+IXHbb83qzqVd
qossI/HtY8XL9iuFuGah/NKD6OfFEvW1XOoKRgupiiXEG14ETzI1WaQIecaftW+u
8222YcNVJTSnzD/zixSIIqp3Qhu4lE1g2J/RA7/xJcexr/HFFKb1+Si70fzvpr8V
niIyW/chI+cvJkxevhfmNW8S3L90s+y5AQ0EYJ6eahAEAPIE6Jll1BLoqgxff43N
bztEuH4WAaM6Zq5N9qHKq4gIhTwY0GjGHxzm2XO642LAIayOqp3UuU0Lf1WOcalZ
cv1GEoF44otmFy0MxTTDlJZvT5DjGu9qAhUEqrnbOuiTVSSg2++ab5auaPvZQxE+
8faso3P5axRlwrFyJdy8KliPAAQLA/94FTmaNZbQPHGtSC16sIBNSg19rDVR58y0
ut/8kCh8JlDCayJTYgC6syiwYh3m1dTUVlGZ4E00WYJvhUgyO5RSk5NvsxExByYI
siLLQt4oDsqi9LLvcl1/asuClhdJaIUYv/bZfW4kF3TC7PMK7oijj28X/dqra07E
ior2jsTAmYi8BBgBCgAmFiEEPgCs7kr2AbQlRyQzNbUaysZUBLAFAmCenmoCGwwF
CQHhM4AACgkQNbUaysZUBLBxxQP+N+JNO9RBXKqhH4lCpD+xXL/SS6fvmAinGQaY
aG24MU6JjL7QCh4vDihQCfLOCVRF8nxPoPqfDbw4uU5pjvqHt6PUKpgB5DZiKAUm
/bvUk063Fuvgne4cxlEOfYENFS9E2heMMHht0F224rPUgdaqN42vKSEfL7eonkaN
FlpyVL0=
=Y47P
-----END PGP PUBLIC KEY BLOCK-----
$ gpg --show-keys lookup.key 
pub   rsa1024 2021-05-14 [SCEA] [expires: 2022-05-14]
      3E00ACEE4AF601B42547243335B51ACAC65404B0
uid                      MM-PNO:201701012393
uid                      alice
sub   elg1024 2021-05-14 [E] [expires: 2022-05-14]
```

Read alice-bank-id.key with a HKP lookup *index* operation:

```
$ curl "http://127.0.0.1:4436/pks/lookup?op=index&search=0x3E00ACEE4AF601B4"
{
  "keys": [
    {
      "fingerprint": "3E00ACEE4AF601B42547243335B51ACAC65404B0",
      "keyId": "3E00ACEE4AF601B4",
      "nym": "alice",
      "personalNumber": "201701012393",
      "userIds": [
        "alice"
      ],
      "verified": true
    }
  ]
}
```

The above return format is somewhat non-standard but the HKP
specification is rather vague on the format anyway.

The gpg command tool can also be used to receive a key using a HKP
lookup:

```
$ gpg --dry-run --keyserver hkp://localhost:4436 --recv-keys 3E00ACEE4AF601B4
gpg: key 35B51ACAC65404B0: rejected by import screener
gpg: Total number processed: 1
```

Life is good!

TONY: Actually it is not good because of the "rejected by import
screener". Can you see why this happens? I am stumped!!

## Perform a HKP pks/add operation

Add chuck.key.key with a HKP add request:

```
$ curl -X POST -H "Content-Type: application/octet-stream" --data-binary @chuck.key http://127.0.0.1:4436/pks/add
```

No news is good news!
