all:
	cd inject; make -f Makefile 
	cd dsepatch; make -f Makefile

clean:
	cd inject; make -f Makefile clean
	cd dsepatch; make -f Makefile clean
