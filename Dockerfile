FROM ubuntu:latest

# RUN touch /conf.yml
RUN mkdir /certs
RUN mkdir /config
# RUN mkdir -p /etc/letsencrypt/live/
# RUN mkdir -p /etc/letsencrypt/archive

EXPOSE 443/tcp

ADD main /main

CMD /main
