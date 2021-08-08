all:
	cd inject; make -f Makefile 
	cd payload; make -f Makefile

clean:
	cd inject; make -f Makefile clean
	cd payload; make -f Makefile clean
