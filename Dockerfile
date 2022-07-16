FROM python:3.9-slim-buster

RUN apt-get update \
&& apt-get install gcc -y \
&& apt-get clean

COPY . /usr/src/mobsfscan

WORKDIR /usr/src/mobsfscan

RUN pip install -e .

ENTRYPOINT ["mobsfscan"]