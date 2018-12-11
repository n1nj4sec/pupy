FROM debian:stretch-slim

LABEL maintainer "alxchk@gmail.com"

ENV DEBIAN_FRONTEND noninteractive
RUN echo 'deb http://ftp.debian.org/debian stretch-backports main' >>/etc/apt/sources.list && \
    apt-get update && \
    mkdir -p /usr/share/man/man1/ && \
    apt-get install -t stretch-backports --no-install-recommends -y build-essential libssl1.0-dev libffi-dev \
    python-dev python-pip openssh-server tmux sslh libcap2-bin \
    john vim-tiny less osslsigncode nmap net-tools libmagic1 \
    autoconf automake unzip libtool locales ncurses-term bash tcpdump libpam-cap netbase \
    git fuse && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /usr/share/doc* /usr/share/man/* /usr/share/info/*
RUN echo 'en_US.UTF-8 UTF-8' >/etc/locale.gen; locale-gen; echo 'LC_ALL=en_US.UTF-8' >/etc/default/locale
RUN useradd -m -d /home/pupy -s /bin/bash pupy
RUN mkdir -p /var/run/sshd /home/pupy/.config/pupy /home/pupy/.ssh /projects
RUN ln -sf /projects/keys/authorized_keys /home/pupy/.ssh/authorized_keys

COPY conf/pupy.conf.docker /home/pupy/.config/pupy/pupy.conf
COPY conf/.bashrc /home/pupy/.bashrc.pupy
COPY conf/capability.conf /etc/security/capability.conf

RUN chmod +s /usr/sbin/tcpdump
RUN chown pupy:pupy -R /home/pupy; chmod 700 /home/pupy/.ssh
RUN echo 'source /home/pupy/.bashrc.pupy' >> /home/pupy/.bashrc

RUN python -m pip install --upgrade pip six setuptools wheel

COPY . /opt/pupy
RUN cd /opt/pupy && pip install --upgrade -r requirements.txt

ADD https://github.com/gentilkiwi/mimikatz/releases/download/2.1.1-20181209/mimikatz_trunk.zip \
    /opt/mimikatz/mimikatz.zip
RUN cd /opt/mimikatz && unzip mimikatz.zip && rm -f mimikatz.zip
RUN mkdir /opt/uacme
RUN apt-get remove -y autoconf automake python-dev libtool build-essential && \
    apt-get -y autoremove && rm -rf /root/.cache/pip && \
    rm -f /etc/ssh/ssh_host_*; rm -f /tmp/requirements.txt

ENV LANG en_US.UTF-8
ENV LC_ALL en_US.UTF-8

EXPOSE 22 1080 5454 5454/udp 8080
VOLUME [ "/projects" ]

ENTRYPOINT [ "/opt/pupy/conf/pupyenv.sh" ]
CMD [ "default" ]
