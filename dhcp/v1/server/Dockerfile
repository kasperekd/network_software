FROM gcc:latest

WORKDIR /app/server_build 
COPY server/Makefile ./Makefile
COPY server/src ./src/
COPY common /app/common/
COPY server/server.conf ./server.conf
RUN make

CMD ["./dhcp_server"]