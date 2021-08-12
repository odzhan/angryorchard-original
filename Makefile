all:
	cd exploit; make -f Makefile 
	cd dsepatch; make -f Makefile

clean:
	cd exploit; make -f Makefile clean
	cd dsepatch; make -f Makefile clean
