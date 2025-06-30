FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

# install dependencies
RUN apt update
RUN apt install -y cmake g++ git automake libtool libgc-dev bison flex \
                   libfl-dev libgmp-dev libboost-dev libboost-iostreams-dev \
                   libboost-graph-dev llvm pkg-config python3 python3-pip \
                   tcpdump

RUN pip3 install ipaddr scapy ply

# get p4c source code
RUN git clone --recursive https://github.com/p4lang/p4c.git
RUN cd p4c && git checkout cfe574dbc4bf033e27c039d9c8134b21a1788091 && git submodule update --init --recursive
RUN apt install -y protobuf-compiler

# build and install p4c
RUN apt install -y libboost-filesystem-dev
RUN cd p4c && \
    mkdir build && \
    cd build && \
    cmake ..  && \
    make -j4 

RUN cd p4c/build && make install

# install psa-ebpf backend dependencies 
RUN apt install -y clang llvm libelf-dev
RUN cd p4c && python3 backends/ebpf/build_libbpf
