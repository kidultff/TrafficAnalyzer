# 网络流量分析/监控器

## 简介

这是一款**尚未完全开发完毕**网络流量监控工具，使用Python+Scapy编写。可用于监控内网主机流量，可以安装到Openwrt或其他一切能安装Python的主机上，流量经过程序监控的网卡即可实现监控。

程序由两部分组成：

* 1、抓包端（Python3+Scapy+MySQL），抓取网卡流量，并执行分析，并存入MySQL内。
** 目前可以做到：DNS日志、TCP日志、UDP日志、应用识别（可自定义应用特征）
** 未来准备实现：WEB登录鉴权、WEB设置、MAC别名、HTTP日志、ICMP日志、TLS指纹（基于JA3）、资产识别等
* 2、Web端（PHP7），用于展现数据

## 功能截图

### 应用使用日志
![](https://www.mmuaa.com/wp-content/uploads/image/20210207/1612689357893467.png)
### DNS日志
![](https://www.mmuaa.com/wp-content/uploads/image/20210207/1612689383804091.png)
### TCP/UDP日志
![](https://www.mmuaa.com/wp-content/uploads/image/20210207/1612689408528016.png)
![](https://www.mmuaa.com/wp-content/uploads/image/20210207/1612689426393664.png)

## 在OpenWrt上安装本程序

建议使用x86架构主机安装本程序
* 1、git clone本项目

* 2、安装Python3 pip3 PHP7

* `opkg install Python3  python3-pip mariadb-server php7  php7-cgi  php7-mod-hash  php7-mod-json  php7-mod-mbstring  php7-mod-mysqlnd  php7-mod-openssl  php7-mod-pdo  php7-mod-pdo-mysql`

* 3、pip安装PyMySQL

* `pip3 install PyMySQL`

* 4、在MySQL中创建一个数据库，用于存放日志。

* 5、修改`config.py`和web目录下`api.php`
** 在`config.py`中，`mysql_settings`为MySQL连接信息，`interface`为捕捉网卡，`tcp_timeout`为tcp超时时间，tcp连接超过这个时间没有数据传输将结束会话。`udp_timeout`为udp超时时间，由于udp没有连接，所以将直接按照四元组聚合，超过这个时间没有数据将按照结束会话处理。`app_timeout`为应用识别检测超时，应用识别会检测应用使用的开始时间和结束时间，超过这个时间没有发送数据将认为应用使用结束，结束时间将被写入数据库内。
** `api.php`中只需要修改前几行数据库信息即可

* 6、uhttpd添加php脚本支持
** `uci add_list uhttpd.main.interpreter='.php=/usr/bin/php7-cgi'`
** `uci commit uhttpd`
** `/etc/init.d/uhttpd restart`

* 7、web-ta移动到/www内

* 8、回到项目目录，执行Python3 main.py，即可抓日志。待日志传入数据库后，在web端相应目录下(如http://192.168.1.1/web-ta/ )即可看到

## 特征库

项目里的features.txt即为特征库，用于应用识别。自带的特征库很大一部分来源destan19大佬的[OpenAppFilter](https://github.com/destan19/OpenAppFilter/)。

如果觉得默认特征库效果不理想，可以自定义添加或删除特征。特征库格式为：

`app名称:[协议;源端口;目的端口;主机;负载]`

一个app多个特征（或的关系）：

`app名称:[协议;源端口;目的端口;主机;负载,协议;源端口;目的端口;主机;负载,...]`

负载特征格式（在有效负载的第N个字节为xx）：

`有效负载第N字节;负载内容`

多个负载特征可由`|`分割（与的关系）

`#`开头的一行为注释，程序不予解析。

以QQ为例：`QQ:[udp;;;;00:02|-1:03,tcp;;;;02:02|-1:03,tcp;;14000;;,tcp;;8080;;00:ca|01:3c,tcp;;;;00:00|01:00|02:00|03:15]`表示：当协议为UDP，且负载第0字节为0x02，最后一个字节是0x03；或当协议为TCP，负载第2字节为0x02，最后一字节为oxo3；或协议为tcp，目的端口为14000.....时，认为该应用为QQ