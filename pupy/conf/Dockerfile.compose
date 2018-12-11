FROM debian:stretch-slim

LABEL maintainer "alxchk@gmail.com"

ENV DEBIAN_FRONTEND noninteractive
RUN echo 'deb http://ftp.debian.org/debian stretch-backports main' >>/etc/apt/sources.list && \
	apt-get update && \
	mkdir -p /usr/share/man/man1/ && \
	apt-get install -t stretch-backports --no-install-recommends -y \
	libssl1.0-dev libffi-dev python-dev python-pip  \
	unzip libtool locales ncurses-term tcpdump \
	netbase fuse && apt-get clean && \
	rm -rf /var/lib/apt/lists/* /usr/share/doc* /usr/share/man/* /usr/share/info/*
RUN echo 'en_US.UTF-8 UTF-8' >/etc/locale.gen; locale-gen; echo 'LC_ALL=en_US.UTF-8' >/etc/default/locale

RUN chmod +s /usr/sbin/tcpdump

RUN python -m pip install --no-cache-dir --upgrade pip six setuptools wheel

RUN mkdir -p /opt/external /project

COPY ./requirements.txt /opt/requirements.txt
COPY ./external/pykcp /opt/external/pykcp

RUN cd /opt && pip install --no-cache-dir --upgrade -r requirements.txt && rm -rf /opt && mkdir -p /opt/pupy

ADD https://github.com/gentilkiwi/mimikatz/releases/download/2.1.1-20181209/mimikatz_trunk.zip \
	/opt/mimikatz/mimikatz.zip

RUN cd /opt/mimikatz && unzip mimikatz.zip && rm -f mimikatz.zip

RUN apt-get remove -y autoconf automake libssl1.0-dev libffi-dev python-dev \
	libtool build-essential && apt-get -y autoremove && \
	rm -rf /root/.cache/pip && rm -f /tmp/requirements.txt

ENV LANG en_US.UTF-8
ENV LC_ALL en_US.UTF-8

EXPOSE 1080 5454 5454/udp 8080

ENTRYPOINT [ "/opt/pupy/conf/pupysh.sh" ]
