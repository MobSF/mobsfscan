FROM python:3.12-slim

RUN apt-get update \
&& apt-get install gcc -y \
&& apt-get clean

COPY . /usr/src/mobsfscan

WORKDIR /usr/src/mobsfscan

RUN pip install --no-cache-dir -e .

ENTRYPOINT ["mobsfscan"]
