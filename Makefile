all:
	(cd src && $(MAKE) all)
	(cd test && $(MAKE) all)
	(cd priv && $(MAKE) all)

clean:
	(cd test && $(MAKE) clean)
	(cd src && $(MAKE) clean)
	(cd priv && $(MAKE) clean)

runtest:
	(cd test && $(MAKE) runtest)
