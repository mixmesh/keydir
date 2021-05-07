#@BEGIN-TEST-DEFAULT-RULES@
ERLC=$(shell which erlc)
ERLC_FLAGS=-I ../.. +debug_info -Ddebug
ERL_HEADERS=$(wildcard *.hrl) $(wildcard ../../*/include/*.hrl)
ERL_SOURCES=$(wildcard *.erl)
ERL_OBJECTS=$(ERL_SOURCES:%.erl=%.beam)
ALL_OBJECTS=$(ERL_OBJECTS)
GPG=gpg

all: $(ALL_OBJECTS) alice.key alice-bank-id.key bob.key chuck.key fred.key

$(ERL_OBJECTS): $(ERL_HEADERS)

alice.key:
	./mkkey alice.key alice

alice-bank-id.key:
	./mkkey alice-bank-id.key alice "MIXMESH-PERSONAL-NUMBER:201701012393"

bob.key:
	./mkkey bob.key "MIXMESH-NYM:bob"

chuck.key:
	./mkkey chuck.key alice bob "MIXMESH-NYM:alice"

fred.key:
	./mkkey fred.key "MIXMESH-NYM:fred"

clean:
	rm -f $(ALL_OBJECTS) *.core *.key

%.beam: %.erl
	env $(ERLC) $(ERLC_FLAGS) $<
#@END-TEST-DEFAULT-RULES@

runtest: all
	rm -f /tmp/mixmesh/keydir-service/keydir_service; ../../mixmesh/bin/run_test --config ../../mixmesh/etc/mixmesh-keydir-only.conf .
