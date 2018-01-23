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

demo_s: build
	./_build/default/test/demo_s.exe

demo_f: build

clean:
	jbuilder clean

