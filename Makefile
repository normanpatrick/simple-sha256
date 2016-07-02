rebuild: clean build

build:
	@echo "  + Building ..."
	@gcc -Wall -o simple.exe simple-sha256.c -D_TESTMAIN -D_DEBUG_SHA2

clean:
	@echo "  + Cleaning..."
	@rm -f simple.exe


