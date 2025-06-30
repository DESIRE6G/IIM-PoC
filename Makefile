

SHELL := /bin/bash
P4C_REPO := /home/p4/p4c

#
# ENVIRONMENT SETUP
#

p4c-docker-setup:
	cd p4c-docker && bash build.sh

nikss-setup:
	sudo apt install jq
	cd nikss && git submodule update --init --recursive
	sudo apt install make cmake gcc git libgmp-dev libelf-dev zlib1g-dev libjansson-dev
	cd nikss && ./build_libbpf.sh
	cd nikss && mkdir -p build && cd build && cmake .. && make -j4

python-setup:
	python3 -m venv .venv
	source .venv/bin/activate && python3 -m pip install git+https://github.com/Team-P4RROT/P4RROT.git@main
	source .venv/bin/activate && python3 -m pip install influxdb-client

download-videos:
	bash scripts/download-sample-videos.sh

#
# BUILD
#

p4rrot-codegen:
	rm -f -r tmp
	cp -r p4src tmp
	source .venv/bin/activate && python3 pysrc/codegen.py

build: p4rrot-codegen
	rm -f -r p4c-docker/p4c-home/p4src
	mkdir -p p4c-docker/p4c-home
	cp -r tmp p4c-docker/p4c-home/p4src
	sudo docker run -it  -v $(PWD)/p4c-docker/p4c-home:/home mytoolset/p4c-ebpf:latest bash -c "cd /home/p4src; make -f /p4c/backends/ebpf/runtime/kernel.mk P4ARGS='' BPFOBJ=out.o P4FILE=main.p4 P4C=p4c-ebpf psa" 
	rm -f -r out && mkdir out
	cp p4c-docker/p4c-home/p4src/out.c out/out.c
	cp p4c-docker/p4c-home/p4src/out.o out/out.o
	cp p4c-docker/p4c-home/p4src/out.bc out/out.bc

#
# TESTBED AND DEMO
#

hw-build: p4rrot-codegen
	rm -f -r out && mkdir out
	cd out && make -f $(P4C_REPO)/backends/ebpf/runtime/kernel.mk BPFOBJ=out.o P4ARGS='' P4FILE=../tmp/main.p4 P4C=p4c-ebpf psa

netns-testbed-up:
	sudo bash scripts/netns-testbed-up.sh

netns-testbed-ping:
	sudo bash scripts/netns-testbed-ping.sh

netns-testbed-down:
	sudo bash scripts/netns-testbed-down.sh
