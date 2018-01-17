PROJECT= ok_socks5

.PHONY: build, install test demo clean

build:
	jbuilder build

install: build
	jbuilder install

uninstall: build
	jbuilder uninstall

test:
	jbuilder runtest

demo: build
	./_build/default/test/demo.exe

clean:
	jbuilder clean

