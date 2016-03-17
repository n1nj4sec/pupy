FROM python:2.7
MAINTAINER Slawomir Rozbicki <docker@rozbicki.eu>

COPY . /pupy
WORKDIR /pupy

RUN pip install -r requirements.txt

EXPOSE 443
CMD ["/usr/local/bin/python", "/pupy/pupy/pupysh.py"]
