FROM debian:stretch-slim

LABEL maintainer "alxchk@gmail.com"

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get install --no-install-recommends -y build-essential python-dev python-pip openssh-server tmux libssh-dev libssl1.0-dev autoconf automake libffi-dev unzip && apt-get clean && rm -rf /var/lib/apt/lists/* /usr/share/doc* /usr/share/man/* /usr/share/info/*
RUN python -m pip install --upgrade setuptools wheel pip
RUN useradd -m -d /home/pupy pupy
RUN mkdir -p /var/run/sshd /home/pupy/.config/pupy /home/pupy/projects/default /home/pupy/.ssh
RUN ln -sf /home/pupy/projects/keys/authorized_keys /home/pupy/.ssh/authorized_keys
COPY conf/pupy.conf.docker /home/pupy/.config/pupy/pupy.conf.default
COPY conf/pupyenv.sh /pupyenv.sh
ADD . /opt/pupy
RUN chown pupy:pupy -R /home/pupy; chmod 700 /home/pupy/.ssh
RUN chmod +x /pupyenv.sh
ADD https://github.com/gentilkiwi/mimikatz/releases/download/2.1.0-20170305/mimikatz_trunk.zip /opt/mimikatz/mimikatz.zip
RUN cd /opt/mimikatz; unzip /opt/mimikatz/mimikatz.zip
RUN pip install -r /opt/pupy/requirements.txt
RUN apt-get remove -y autoconf automake python-dev build-essential libssh-dev libssl-dev; apt-get -y autoremove; rm -rf /root/.cache/pip

EXPOSE 22 53 9999
VOLUME /home/pupy/projects

ENTRYPOINT [ "/pupyenv.sh" ]
