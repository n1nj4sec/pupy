FROM debian:jessie-slim

LABEL maintainer "alxchk@gmail.com"

ENV DEBIAN_FRONTEND noninteractive
RUN echo 'deb http://ftp.debian.org/debian jessie-backports main' >>/etc/apt/sources.list && \
    apt-get update && \
    apt-get install -t jessie-backports --no-install-recommends -y build-essential \
    python-dev python-pip openssh-server tmux sslh libssl-dev libcap2-bin \
    john vim-nox less \
    autoconf automake libffi-dev unzip libtool locales ncurses-term bash tcpdump libpam-cap && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /usr/share/doc* /usr/share/man/* /usr/share/info/*
RUN echo 'en_US.UTF-8 UTF-8' >/etc/locale.gen; locale-gen; echo 'LC_ALL=en_US.UTF-8' >/etc/default/locale
RUN python -m pip install --upgrade setuptools wheel pip
RUN useradd -m -d /home/pupy -s /bin/bash pupy
RUN mkdir -p /var/run/sshd /home/pupy/.config/pupy /home/pupy/.ssh /projects
RUN ln -sf /projects/keys/authorized_keys /home/pupy/.ssh/authorized_keys

COPY conf/pupy.conf.docker /home/pupy/.config/pupy/pupy.conf
COPY conf/.bashrc /home/pupy/.bashrc.pupy
COPY conf/capability.conf /etc/security/capability.conf

RUN chmod +s /usr/sbin/tcpdump
RUN chown pupy:pupy -R /home/pupy; chmod 700 /home/pupy/.ssh
RUN echo 'source /home/pupy/.bashrc.pupy' >> /home/pupy/.bashrc

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt --no-binary :all:

COPY . /opt/pupy

ADD https://github.com/gentilkiwi/mimikatz/releases/download/2.1.1-20170328/mimikatz_trunk.zip \
    /opt/mimikatz/mimikatz.zip
RUN cd /opt/mimikatz && unzip mimikatz.zip && rm -f mimikatz.zip
RUN apt-get remove -y autoconf automake python-dev libtool build-essential libssl-dev && \
    apt-get -y autoremove && rm -rf /root/.cache/pip && \
    rm -f /etc/ssh/ssh_host_*; rm -f /tmp/requirements.txt

ENV LANG en_US.UTF-8
ENV LC_ALL en_US.UTF-8

EXPOSE 22 1080 5454 5454/udp 8080
VOLUME [ "/projects" ]

ENTRYPOINT [ "/opt/pupy/conf/pupyenv.sh" ]
CMD [ "default" ]
