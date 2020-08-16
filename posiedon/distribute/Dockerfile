FROM ubuntu:18.04

RUN apt-get update

RUN useradd -d /home/challenge/ -m -p challenge -s /bin/bash challenge
RUN echo "challenge:challenge" | chpasswd
 
WORKDIR /home/challenge
COPY ./share/cards .
COPY ./share/flag .
COPY ./share/ynetd .
COPY ./share/run.sh .
COPY ./share/libc-2.32.so .
COPY ./share/ld-2.32.so .

RUN chown -R root:root /home/challenge/

USER challenge
CMD ./run.sh
