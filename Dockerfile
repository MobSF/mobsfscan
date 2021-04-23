FROM python:3.8-slim-buster

COPY . /usr/src/mobsfscan

WORKDIR /usr/src/mobsfscan

RUN pip install -e .

ENTRYPOINT ["mobsfscan"]