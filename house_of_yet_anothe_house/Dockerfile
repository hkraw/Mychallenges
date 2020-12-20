FROM ubuntu:20.04

RUN apt-get update

RUN useradd -d /home/challenge/ -m -p challenge -s /bin/bash challenge
RUN echo "challenge:challenge" | chpasswd

WORKDIR /home/challenge
COPY ./challenge/house-of-yet_another_house .
COPY ./challenge/flag.txt .
COPY ./challenge/ynetd .
COPY ./challenge/run.sh .
COPY ./challenge/libc-2.32.so .
COPY ./challenge/ld-2.32.so .

RUN chown -R root:root /home/challenge/

USER challenge
CMD ./run.sh

