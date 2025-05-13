FROM gcc:latest

WORKDIR /app/client_build
COPY client/Makefile ./Makefile
COPY client/src ./src/
COPY common /app/common/
COPY client/configs ./configs/ 
RUN make

CMD ["./dhcp_client", "configs/client1.conf"] 