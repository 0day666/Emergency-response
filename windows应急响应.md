## windows 入侵排查

* [windows 入侵排查](#windows-入侵排查)
  * [0x00 前言](#0x00-前言)
  * [0x01 入侵排查思路](#0x01-入侵排查思路)
    * [1\.1 检查系统账号安全](#11-检查系统账号安全)
    * [1\.2 检查异常端口、进程](#12-检查异常端口进程)
    * [1\.3 检查启动项、计划任务、服务](#13-检查启动项计划任务服务)
    * [1\.4 检查系统相关信息](#14-检查系统相关信息)
    * [1\.7 自动化查杀](#17-自动化查杀)
  * [0x02 工具篇](#0x02-工具篇)
    * [2\.1 病毒分析](#21-病毒分析)
    * [2\.2 病毒查杀](#22-病毒查杀)
    * [2\.3 病毒动态](#23-病毒动态)
    * [2\.4 在线病毒扫描网站](#24-在线病毒扫描网站)
    * [2\.5 webshell查杀](#25-webshell查杀)

![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635747451162-de8d18c7-211d-4df3-b629-d2269b278386.png#clientId=ub4b40aed-bab4-4&from=paste&height=435&id=ub2a1460d&margin=%5Bobject%20Object%5D&name=image.png&originHeight=869&originWidth=1716&originalType=binary&ratio=1&size=188660&status=done&style=none&taskId=u7272b8a1-3b64-4f51-b4e9-04e20e1d293&width=858)
------

### 0x00 前言
当企业发生黑客入侵、系统崩溃或其它影响业务正常运行的安全事件时，急需第一时间进行处理，使企业的网络信息系统在最短时间内恢复正常工作，进一步查找入侵来源，还原入侵事故过程，同时给出解决方案与防范措施，为企业挽回或减少经济损失。
常见的应急响应事件分类：
Web 入侵：网页挂马、主页篡改、Webshell
系统入侵：病毒木马、勒索软件、远控后门
网络攻击：DDOS 攻击、DNS 劫持、ARP 欺骗
针对常见的攻击事件，结合工作中应急响应事件分析和解决的方法，总结了一些 Windows 服务器入侵排查的思路。

------

### 0x01 入侵排查思路
#### 1.1 检查系统账号安全
1、查看服务器是否有弱口令，远程管理端口是否对公网开放。

- 检查方法：据实际情况咨询相关服务器管理员。

2、查看服务器是否存在可疑账号、新增账号。

- 检查方法：

a、打开 cmd 窗口，输入 lusrmgr.msc 命令，查看是否有新增/可疑的账号
b、查看注册表HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\
c、输入net user命令查看系统用户
3、查看服务器是否存在隐藏账号、克隆账号。

- 检查方法：

a、打开注册表 ，查看管理员对应键值。
b、使用D盾_web查杀工具，集成了对克隆账号检测的功能。
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635750776062-1b77a49c-75b0-49a0-81a1-88b6a072d310.png#clientId=ubce01d3b-324e-4&from=paste&height=328&id=ue01f4b15&margin=%5Bobject%20Object%5D&name=image.png&originHeight=655&originWidth=1261&originalType=binary&ratio=1&size=133131&status=done&style=none&taskId=u4c9ba289-6351-4711-8dd1-8423a4375b5&width=630.5)
4、结合日志，查看管理员登录时间、用户名是否存在异常。

- 检查方法：

a、Win+R 打开运行，输入"eventvwr.msc"，回车运行，打开“事件查看器”。
b、导出 Windows 日志 -- 安全，利用微软官方工具 [Log Parser](https://www.microsoft.com/en-us/download/details.aspx?id=24659) 进行分析。
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635750820570-e18459d6-fe52-4c52-bbce-25207cdeee50.png#clientId=ubce01d3b-324e-4&from=paste&height=349&id=u93e96baf&margin=%5Bobject%20Object%5D&name=image.png&originHeight=698&originWidth=1084&originalType=binary&ratio=1&size=73703&status=done&style=none&taskId=u7c766bba-c168-4be2-8935-9f93ea47a3c&width=542)
#### 1.2 检查异常端口、进程
1、检查端口连接情况，是否有远程连接、可疑连接。

- 检查方法：

a、使用netstat -ano 命令查看目前的网络连接，定位可疑的 ESTABLISHED
b、根据 netstat 命令定位出的 PID 编号，再通过 tasklist 命令进行进程定位 tasklist | findstr "PID"
![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635750879776-9e190ee8-761f-45ae-a0c3-436942e09d91.png#clientId=ubce01d3b-324e-4&from=paste&height=398&id=u0ec88d90&margin=%5Bobject%20Object%5D&name=image.png&originHeight=795&originWidth=1036&originalType=binary&ratio=1&size=47841&status=done&style=none&taskId=uadbd5596-265d-4f61-ac27-bbe469edf0b&width=518)
2、进程

- 检查方法：

a、开始 -- 运行 -- 输入 msinfo32 命令，依次点击 "软件环境 -- 正在运行任务" 就可以查看到进程的详细信息，比如进程路径、进程ID、文件创建日期以及启动时间等。
b、打开D盾_web查杀工具，进程查看，关注没有签名信息的进程。
c、通过微软官方提供的 Process Explorer 等工具进行排查 。
d、查看可疑的进程及其子进程。可以通过观察以下内容：  
```
没有签名验证信息的进程   
没有描述信息的进程   
进程的属主   
进程的路径是否合法   
CPU 或内存资源占用长时间过高的进程 
```
3、小技巧：
a、查看端口对应的 PID：netstat -ano | findstr "port"
b、查看进程对应的 PID：任务管理器 -- 查看 -- 选择列 -- PID 或者 tasklist | findstr "PID"
c、查看进程对应的程序位置：
任务管理器 -- 选择对应进程 -- 右键打开文件位置
运行输入 wmic，cmd 界面输入 process
d、tasklist /svc 进程 -- PID -- 服务
e、查看Windows服务所对应的端口：
%systemroot%/system32/drivers/etc/services（一般 %systemroot% 就是 C:\Windows 路径）
#### 
#### 1.3 检查启动项、计划任务、服务
1、检查服务器是否有异常的启动项。

- 检查方法：

a、登录服务器，单击【开始】>【所有程序】>【启动】，默认情况下此目录在是一个空目录，确认是否有非业务程序在该目录下。 
b、单击开始菜单 >【运行】，输入msconfig，查看是否存在命名异常的启动项目，是则取消勾选命名异常的启动项目，并到命令中显示的路径删除文件。 
c、单击【开始】>【运行】，输入regedit打开注册表，查看开机启动项是否正常，特别注意如下三个注册表项：
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Runonce
```
  检查启动项是否有启动异常的项目，如有请删除，并建议安装杀毒软件进行病毒查杀，清除残留病毒或木马。
d、利用安全软件查看启动项、开机时间管理等。
e、输入命令查看启动项wmic startup list full
​

2、检查计划任务

- 检查方法：

a、单击【开始】>【设置】>【控制面板】>【任务计划】，查看计划任务属性，便可以发现木马文件的路径
b、单击【开始】>【运行】；输入cmd，然后输入at，检查计算机与网络上的其它计算机之间的会话或计划任务，如有，则确认是否为正常连接。
​

3、服务自启动

- 检查方法：单击【开始】>【运行】，输入services.msc，注意服务状态和启动类型，检查是否有异常服务。



#### 1.4 检查系统相关信息
1、查看系统版本以及补丁信息

- 检查方法：单击【开始】>【运行】，输入systeminfo，查看系统信息。

2、查找可疑目录及文件

- 检查方法：

a、查看用户目录，新建账号会在这个目录生成一个用户目录，查看是否有新建用户目录。
```
Window 2003版本 C:\Documents and Settings
Window 2008R2及以后版本 C:\Users\
```
b、单击【开始】>【运行】，输入%UserProfile%\Recent，分析最近打开分析可疑文件。 
c、在服务器各个目录，可根据文件夹内文件列表时间进行排序，查找可疑文件。 
d、回收站、浏览器下载目录、浏览器历史记录 
e、修改时间在创建时间之前的为可疑文件
​

3、发现并得到 WebShell、远控木马的创建时间，如何找出同一时间范围内创建的文件？
a、利用 Registry Workshop注册表编辑器的搜索功能，可以找到最后写入时间区间的文件。 
b、利用计算机自带文件搜索功能，指定修改时间进行搜索。 
#### 
1.5  Windows日志分析
**1、Windows事件日志简介**
 	Windows系统日志是记录系统中硬件、软件和系统问题的信息，同时还可以监视系统中发生的事件。用户可以通过它来检查错误发生的原因，或者寻找受到攻击时攻击者留下的痕迹。
Windows主要有以下三类日志记录系统事件：应用程序日志、系统日志和安全日志。
**系统日志**
记录操作系统组件产生的事件，主要包括驱动程序、系统组件和应用软件的崩溃以及数据丢失错误等。系统日志中记录的时间类型由Windows NT/2000操作系统预先定义。 默认位置： %SystemRoot%\System32\Winevt\Logs\System.evtx 
**应用程序日志**
包含由应用程序或系统程序记录的事件，主要记录程序运行方面的事件，例如数据库程序可以在应用程序日志中记录文件错误，程序开发人员可以自行决定监视哪些事件。如果某个应用程序出现崩溃情况，那么我们可以从程序事件日志中找到相应的记录，也许会有助于你解决问题。  默认位置：%SystemRoot%\System32\Winevt\Logs\Application.evtx 
**安全日志**
记录系统的安全审计事件，包含各种类型的登录日志、对象访问日志、进程追踪日志、特权使用、帐号管理、策略变更、系统事件。安全日志也是调查取证中最常用到的日志。默认设置下，安全性日志是关闭的，管理员可以使用组策略来启动安全性日志，或者在注册表中设置审核策略，以便当安全性日志满后使系统停止响应。 默认位置：%SystemRoot%\System32\Winevt\Logs\Security.evtx 
系统和应用程序日志存储着故障排除信息，对于系统管理员更为有用。 安全日志记录着事件审计信息，包括用户验证（登录、远程访问等）和特定用户在认证后对系统做了什么，对于调查人员而言，更有帮助。
​

**2、审核策略与事件查看器**
   Windows Server 2008 R2 系统的审核功能在默认状态下并没有启用 ，建议开启审核策略，若日后系统出现故障、安全事故则可以查看系统的日志文件，排除故障，追查入侵者的信息等。
PS：默认状态下，也会记录一些简单的日志，日志默认大小20M
**设置1**：开始 → 管理工具 → 本地安全策略 → 本地策略 → 审核策略
**设置2**：设置合理的日志属性，即日志最大大小、事件覆盖阀值等：
**查看系统日志方法：**

1. 在“开始”**菜单上，依次指向**“所有程序”**、**“管理工具”**，然后单击**“事件查看器”
1. 按 "**Window+R**"，输入 ”**eventvwr.msc**“ 也可以直接进入“**事件查看器**”

![image.png](https://cdn.nlark.com/yuque/0/2021/png/1660081/1635751096319-ec384c06-8234-46ba-a26c-8b70daa0617a.png#clientId=ubce01d3b-324e-4&from=paste&height=360&id=O0JkI&margin=%5Bobject%20Object%5D&name=image.png&originHeight=719&originWidth=1089&originalType=binary&ratio=1&size=86587&status=done&style=none&taskId=u5ea3c695-732b-45d7-803a-151f17e67c1&width=544.5)
**​**

**3、事件日志分析**
对于Windows事件日志分析，不同的EVENT ID代表了不同的意义，摘录一些常见的安全事件的说明：

| **事件ID** | **说明** |
| --- | --- |
| 4624 | 登录成功 |
| 4625 | 登录失败 |
| 4634 | 注销成功 |
| 4647 | 用户启动的注销 |
| 4672 | 使用超级用户（如管理员）进行登录 |
| 4720 | 创建用户 |

每个成功登录的事件都会标记一个登录类型，不同登录类型代表不同的方式：

| **登录类型** | **描述** | **说明** |
| --- | --- | --- |
| 2 | 交互式登录（Interactive） | 用户在本地进行登录。 |
| 3 | 网络（Network） | 最常见的情况就是连接到共享文件夹或共享打印机时。 |
| 4 | 批处理（Batch） | 通常表明某计划任务启动。 |
| 5 | 服务（Service） | 每种服务都被配置在某个特定的用户账号下运行。 |
| 7 | 解锁（Unlock） | 屏保解锁。 |
| 8 | 网络明文（NetworkCleartext） | 登录的密码在网络上是通过明文传输的，如FTP。 |
| 9 | 新凭证（NewCredentials） | 使用带/Netonly参数的RUNAS命令运行一个程序。 |
| 10 | 远程交互，（RemoteInteractive） | 通过终端服务、远程桌面或远程协助访问计算机。 |
| 11 | 缓存交互（CachedInteractive） | 以一个域用户登录而又没有域控制器可用 |

关于更多EVENT ID，详见微软官方网站上找到了“Windows Vista 和 Windows Server 2008 中的安全事件的说明”。
原文链接 ：[https://support.microsoft.com/zh-cn/help/977519/description-of-security-events-in-windows-7-and-in-windows-server-2008](https://support.microsoft.com/zh-cn/help/977519/description-of-security-events-in-windows-7-and-in-windows-server-2008)
​

**4、Windows日志分析工具**
**（1）Log Parser**
Log Parser（是微软公司出品的日志分析工具，它功能强大，使用简单，可以分析基于文本的日志文件、XML 文件、CSV（逗号分隔符）文件，以及操作系统的事件日志、注册表、文件系统、Active Directory。它可以像使用 SQL 语句一样查询分析这些数据，甚至可以把分析结果以各种图表的形式展现出来。
Log Parser 2.2下载地址：[https://www.microsoft.com/en-us/download/details.aspx?id=24659](https://www.microsoft.com/en-us/download/details.aspx?id=24659)
Log Parser 使用示例：[https://mlichtenberg.wordpress.com/2011/02/03/log-parser-rocks-more-than-50-examples/](https://mlichtenberg.wordpress.com/2011/02/03/log-parser-rocks-more-than-50-examples/)
**基本查询结构**
Logparser.exe –i:EVT –o:DATAGRID "SELECT * FROM c:\xx.evtx" 
**使用Log Parser分析日志**
1、查询登录成功的事件
```
登录成功的所有事件
LogParser.exe -i:EVT –o:DATAGRID  "SELECT *  FROM c:\Security.evtx where EventID=4624"

指定登录时间范围的事件：
LogParser.exe -i:EVT –o:DATAGRID  "SELECT *  FROM c:\Security.evtx where TimeGenerated>'2018-06-19 23:32:11' and TimeGenerated<'2018-06-20 23:34:00' and EventID=4624"

提取登录成功的用户名和IP：
LogParser.exe -i:EVT  –o:DATAGRID  "SELECT EXTRACT_TOKEN(Message,13,' ') as EventType,TimeGenerated as LoginTime,EXTRACT_TOKEN(Strings,5,'|') as Username,EXTRACT_TOKEN(Message,38,' ') as Loginip FROM c:\Security.evtx where EventID=4624"
```
2、查询登录失败的事件
```
登录失败的所有事件：
LogParser.exe -i:EVT –o:DATAGRID  "SELECT *  FROM c:\Security.evtx where EventID=4625"

提取登录失败用户名进行聚合统计：
LogParser.exe  -i:EVT "SELECT  EXTRACT_TOKEN(Message,13,' ')  as EventType,EXTRACT_TOKEN(Message,19,' ') as user,count(EXTRACT_TOKEN(Message,19,' ')) as Times,EXTRACT_TOKEN(Message,39,' ') as Loginip FROM c:\Security.evtx where EventID=4625 GROUP BY Message" 


```
3、系统历史开关机记录：
```
LogParser.exe -i:EVT –o:DATAGRID  "SELECT TimeGenerated,EventID,Message FROM c:\System.evtx where EventID=6005 or EventID=6006"
```
**​**

**（2）LogParser Lizard**
对于GUI环境的Log Parser Lizard，其特点是比较易于使用，甚至不需要记忆繁琐的命令，只需要做好设置，写好基本的SQL语句，就可以直观的得到结果。
下载地址：[http://www.lizard-labs.com/log_parser_lizard.aspx](http://www.lizard-labs.com/log_parser_lizard.aspx)
依赖包：Microsoft .NET Framework 4 .5，下载地址：[https://www.microsoft.com/en-us/download/details.aspx?id=42642](https://www.microsoft.com/en-us/download/details.aspx?id=42642)


**（3）Event Log Explorer**
Event Log Explorer是一款非常好用的Windows日志分析工具。可用于查看，监视和分析跟事件记录，包括安全，系统，应用程序和其他微软Windows 的记录被记载的事件，其强大的过滤功能可以快速的过滤出有价值的信息。
下载地址：[https://event-log-explorer.en.softonic.com/](https://event-log-explorer.en.softonic.com/)
​

#### 1.7 自动化查杀

- 病毒查杀：

检查方法：下载安全软件，更新最新病毒库，进行全盘扫描
安全软件下载地址：
```
卡巴斯基：http://devbuilds.kaspersky-labs.com/devbuilds/KVRT/latest/full/KVRT.exe   （推荐理由：绿色版、最新病毒库） 
大蜘蛛：http://free.drweb.ru/download+cureit+free（推荐理由：扫描快、一次下载只能用1周，更新病毒库） 
火绒安全软件：https://www.huorong.cn 
360杀毒：http://sd.360.cn/download_center.html 
```

- Webshell查杀

检查方法：选择具体站点路径进行Webshell查杀，建议使用两款 WebShell 查杀工具同时查杀，可相互补充规则库的不足。
查杀工具下载地址
```
D盾_Web查杀：http://www.d99net.net/index.asp
河马 WebShell 查杀：http://www.shellpub.com
```


------

### 0x02 工具篇

#### 2.1 病毒分析
PCHunter：[http://www.xuetr.com](http://www.xuetr.com)
火绒剑：[https://www.huorong.cn](https://www.huorong.cn)
Process Explorer：[https://docs.microsoft.com/zh-cn/sysinternals/downloads/process-explorer](https://docs.microsoft.com/zh-cn/sysinternals/downloads/process-explorer)
processhacker：[https://processhacker.sourceforge.io/downloads.php](https://processhacker.sourceforge.io/downloads.php)
autoruns：[https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)
OTL：[https://www.bleepingcomputer.com/download/otl/](https://www.bleepingcomputer.com/download/otl/)
SysInspector：[http://download.eset.com.cn/download/detail/?product=sysinspector](http://download.eset.com.cn/download/detail/?product=sysinspector)


#### 2.2 病毒查杀
卡巴斯基：[http://devbuilds.kaspersky-labs.com/devbuilds/KVRT/latest/full/KVRT.exe](http://devbuilds.kaspersky-labs.com/devbuilds/KVRT/latest/full/KVRT.exe)   （推荐理由：绿色版、最新病毒库）
大蜘蛛：http://free.drweb.ru/download+cureit+free（推荐理由：扫描快、一次下载只能用1周，更新病毒库）
火绒安全软件：[https://www.huorong.cn](https://www.huorong.cn)
360杀毒：[http://sd.360.cn/download_center.html](http://sd.360.cn/download_center.html)


#### 2.3 病毒动态
CVERC-国家计算机病毒应急处理中心：[http://www.cverc.org.cn](http://www.cverc.org.cn)
微步在线威胁情报社区：[https://x.threatbook.cn](https://x.threatbook.cn)
火绒安全论坛：[http://bbs.huorong.cn/forum-59-1.html](http://bbs.huorong.cn/forum-59-1.html)
爱毒霸社区：[http://bbs.duba.net](http://bbs.duba.net)
腾讯电脑管家：[http://bbs.guanjia.qq.com/forum-2-1.html](http://bbs.guanjia.qq.com/forum-2-1.html)


#### 2.4 在线病毒扫描网站
Virustotal：[https://www.virustotal.com](https://www.virustotal.com)
Virscan：[http://www.virscan.org](http://www.virscan.org)
腾讯哈勃分析系统：[https://habo.qq.com](https://habo.qq.com)
Jotti 恶意软件扫描系统：[https://virusscan.jotti.org](https://virusscan.jotti.org)


#### 2.5 webshell查杀
D盾_Web查杀：[http://www.d99net.net/index.asp](http://www.d99net.net/index.asp)
河马 WebShell 查杀：[http://www.shellpub.com](http://www.shellpub.com)
