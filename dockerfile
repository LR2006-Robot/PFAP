FROM ubuntu:24.04

RUN sed -i 's|http://archive.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g' /etc/apt/sources.list && \
	sed -i 's|http://security.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g' /etc/apt/sources.list && \
	apt-get update && apt-get install -y --no-install-recommends \
	build-essential \
	cmake \
	git \
	wget \
	ca-certificates \
	libgmp3-dev \
	libproc2-dev \
	libboost-all-dev \
	libssl-dev \
	pkg-config \
	sudo \
	golang-go \
	python3 \
	&& rm -rf /var/lib/apt/lists/*


WORKDIR /root/code
RUN git clone -b PFAP-for-ubuntu24.04 https://github.com/LR2006-Robot/PFAP.git

# COPY ./PFAP /root/code/PFAP
WORKDIR /root/code/PFAP
RUN chmod +x build.sh && ./build.sh all

ENV PATH="/root/go/bin:$PATH"

EXPOSE 2007 2008 8545 30303

CMD ["/bin/bash"]