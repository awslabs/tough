# syntax=docker/dockerfile:1

FROM rust:slim
RUN apt update && apt install -y openssl
RUN cargo install --force --locked tuftool
RUN mkdir /share
ENTRYPOINT ["tuftool"]
