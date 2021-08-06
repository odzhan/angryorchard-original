##
## Disables driver signing enforcement from
## usermode, and loads a requested driver
## into memory.
##
## Do to the lack of a driver and usage of
## a userland bug, this project remains 
## closed source.
##
import cough
import pefile
import argparse

if __name__ in '__main__':
    try:
        parser = argparse.ArgumentParser( description = 'Extracts shellcode from a PE.' );
        parser.add_argument( '-f', required = True, help = 'Path to the source executable', type = str );
        parser.add_argument( '-o', required = True, help = 'Path to store the output raw binary', type = str );
        option = parser.parse_args();

        PeExe = pefile.PE( option.f );
        PeSec = PeExe.sections[0].get_data();

        if PeSec.find( b'ENDOFCODE' ) != None:
            ScRaw = PeSec[ : PeSec.find( b'ENDOFCODE' ) ];
            f = open( option.o, 'wb+' );
            f.write( ScRaw );
            f.close();
        else:
            print('[!] error: no ending tag');
    except Exception as e:
        print( '[!] error: {}'.format( e ) );
