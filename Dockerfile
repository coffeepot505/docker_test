#
# Ubuntu Dockerfile
#
# https://github.com/dockerfile/ubuntu
#

# Pull base image.
FROM ubuntu:12.10
FROM python:2.7

# Update OS.
RUN echo "deb http://archive.ubuntu.com/ubuntu quantal main universe multiverse" > /etc/apt/sources.list
RUN apt-get update
RUN apt-get upgrade -y

# Install basic packages.
RUN apt-get install -y software-properties-common
RUN apt-get install -y curl git htop unzip vim wget

RUN pip install -r requirements.txt
RUN pip install numpy==3.1

# Add files.
ADD root/.bashrc /root/.bashrc
ADD root/.gitconfig /root/.gitconfig
ADD root/scripts /root/scripts

# Set working directory.
ENV HOME /root
WORKDIR /root