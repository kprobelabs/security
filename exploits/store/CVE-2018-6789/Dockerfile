FROM debian:bullseye

WORKDIR /opt

# install required packages via apt
RUN apt-get update && apt-get install -y gcc net-tools vim gdb python3 wget git make procps libpcre3-dev libdb-dev libxt-dev libxaw7-dev

# install exim
RUN useradd exim-demo
COPY ./Exim exim/
RUN mkdir -p exim/src/Local
COPY exim_files/Makefile exim/src/Local/Makefile
COPY exim_files/eximon.conf exim/src/Local/eximon.conf
COPY exim_files/Makefile-Linux exim/src/OS/Makefile-Linux
RUN EXIM_RELEASE_VERSION=4.89 make -C exim/src install
COPY exim_files/configure /usr/exim/configure

# install pwndbg (see https://github.com/pwndbg/pwndbg/blob/dev/Dockerfile)
ENV LANG=en_US.utf8
ENV TZ=Europe/Berlin

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone && \
    apt-get update && \
    apt-get install -y locales && \
    rm -rf /var/lib/apt/lists/* && \
    localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8 && \
    apt-get update && \
    apt-get install -y vim
RUN git clone https://github.com/pwndbg/pwndbg.git && \
    cd pwndbg && \
    git fetch --tags && \
    git checkout 2024.08.29 && \
    ./setup.sh

# install custom debugging scripts for gdb
COPY debugging/gdbinit /root/.gdbinit
COPY debugging/breakpoints debugging/showmem.py ./

# util scripts
COPY scripts/attach_exim.sh scripts/run_exim.sh ./

CMD ["/bin/bash"]
