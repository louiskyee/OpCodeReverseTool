# 使用 Ubuntu 最新版作為基礎映像
FROM ubuntu:latest

# 安裝必要的套件
RUN apt-get update && apt-get install -y git make sudo

RUN useradd -m radare2user\
    && echo "radare2user:radare2user" | chpasswd\
    && adduser radare2user sudo

USER radare2user

workdir /home/radare2user

# 複製安裝腳本到容器中
COPY --chown=radare2user:radare2user install_radare2.sh /install_radare2.sh

# 賦予腳本執行權限
RUN chmod +x /install_radare2.sh

# 當容器啟動時執行腳本
CMD ["/radare2_deploy.sh"]

