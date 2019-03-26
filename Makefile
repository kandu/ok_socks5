PROJECT= ok_socks5

.PHONY: build, install test demo clean

build:
	dune build

install: build
	dune install

uninstall: build
	dune uninstall

test:
	dune runtest

demo_s: build
	./_build/default/test/demo_s.exe

demo_f: build

clean:
	dune clean

