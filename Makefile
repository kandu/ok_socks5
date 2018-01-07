PROJECT= ok_socks5

.PHONY: build, install clean

build:
	jbuilder build

install: build
	jbuilder install

uninstall: build
	jbuilder uninstall

clean:
	jbuilder clean

