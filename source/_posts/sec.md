---
title: 安全学习
date: 2019-07-01 18:50:04
categories: 工具学习
tags: [xss,安全]
---
####  xss 攻击

##### 简介
跨站脚本攻击，攻击方式分为三种：
- 反射类型，不经过数据库，前端处理。输入数据未做校验，当输入数据包含js 脚本时，会对网站造成攻击
- 存储型，经过前端，经过数据库。即未对输入数据做校验，输入数据入库，再次获取时，会执行恶意脚本，执行恶意攻击。
- dom类型，讲解不清晰，待继续查资料

##### 测试说明

xss 常规测试方法是
```
<script>alert(1)</script>
```
验证是否对> < /等做转义处理。

##### 防护方案
1.maven 引入xss 防护jar
2.调用代码在服务端处理入参
3. 在前端展示时调用进行转义

***xss推荐美团的一篇技术分享***：[如何防止xss攻击](https://segmentfault.com/a/1190000016551188)




####  越权攻击
越权攻击分为两种，水平越权和垂直越权
##### 水平越权

###### 简介
水平越权，指用户请求不属于自己的数据时，服务端未对数据属主做校验，使得攻击者可以操作其他用户的数据（增、删、改、查）
对于单个功能点的测试，需要覆盖到增、删、改、查四个基本点，但是具体需要看功能点情况，如果该功能仅能编辑和查询，则不需要增加和删除的防御测试。

###### 测试说明
通用测试：
增删改查账户A的数据，提交时把cookie 改为账户B的，查看对账户A的操作是否成功。

具体测试示例：

a.添加收货地址

insert into address(userId,addressInfo) values(1001, "我的地址")

1. 分析Cookie中是否有值能充当userId，可以修改一试
2. 分析请求的参数中是否有值能充当userId，可以修改一试

b.删除收货地址、修改收货地址 

 delete from address whereaddressId=123456 [and userId=1001]    update   address   set   addressInfo="我的新地址"   where   addressId=123456   [and userId=1001]
1. 如果SQL语句中没有设置userId，那么就存在越权，修改addressId即可
2. 如果SQL语句中设置了userId，分析Cookie中是否有值能充当userId，可以修改一试
3. 如果SQL语句中设置了userId，分析请求的参数中是否有值能充当userId，可以修改一试

c.查询收货地址

查询所有收货地址的详细信息
select * from address where userId=1001
1. 分析Cookie中是否有值能充当userId，可以修改一试
2. 分析请求的参数中是否有值能充当userId，可以修改一试

查询单个收货地址的详细信息

select * from address where addressId=123456 [and userId=1001]
1. 如果SQL语句中没有设置userId，那么就存在越权，修改addressId即可
2. 如果SQL语句中设置了userId，分析Cookie中是否有值能充当userId，可以修改一试
3. 如果SQL语句中设置了userId，分析请求的参数中是否有值能充当userId，可以修改一试

###### 代码规范
越权的代码规范：
提高严谨性（根本方式）
1. 任何和账户相关的增删改查操作都要用当前用户身份去约束。在“越权挖掘”中提到的所有SQL语句，都应当包含userId字段。
2. 所有获取当前用户身份的方式都应该是从session中获取的。
3. 不以任何客户端传递的明文数据作为鉴权方式在“越权挖掘”中提到的所有SQL语句中的userId字段，都不能是客户端传递的（包括Cookie中不能有明文认证信息，请求参数和请求路径中也不能有任何鉴权字段）

提高利用难度（不会解决越权的问题，只能降低越权带来的危害）
4. 用户可见索引字段尽量设置成无规律。

##### 垂直越权
###### 简介
垂直越权指，应用程序没有做权限控制，或者仅在js前端做权限控制，导致攻击者可以猜测到管理页面或者绕过前端验证，获取不属于自己的权限。
###### 测试说明
垂直越权。一般人没有管理员账号，访问路径都不知道就没办法用传统的方式进行越权测试。所以只能先找到路径再进行下一步测试。

查找路径一般有两种：
1. 爆破路径，查看是否泄露一些有用信息
2. 根据命名规则猜测请求路径
###### 代码规范
垂直越权垂直越权可以在访问数据库之前进行拦截，针对垂直越权一般通过划分角色来防御。用户和角色相关联，一个用户可以属于多个角色。一个角色拥有有多个资源的访问权限，当用户访问某个资源时，只需判断当前用户是否属于当前资源对应的角色即可。

Java中有两种较为常用的方案：Spring Security和Apache Shiro。前者提供了基于URL的控制方式及基于表达式的控制方式，功能更强大，但是较复杂，入门成本高；后者相比之下更简单，更容易理解。参考：https://www.secpulse.com/archives/44410.htmlhttps://vincentmi.gitbooks.io/spring-security-reference-zh/content/1_introduction.htmlhttps://www.ibm.com/developerworks/cn/java/j-lo-shiro/


#### 上传漏洞
##### 简介
在处理用户上传文件时，为对文件扩展名进行验证，同时上传文件的路径，文件名、扩展名为用户可控数据时，会存在安全漏洞。用户能够直接上传木马到web服务来控制服务器。

##### 上传漏洞的测试方法（来自视频）
将一个恶意攻击脚本保存为后缀为jpg 的文件，上传至浏览器，修改上传请求中的filename， 保存为恶意脚本本身的格式，执行upload 请求，恶意脚本被成功上传至服务器。

##### 漏洞修复方法
1. 建议基于京东云存储实现文件上传，确保文件存储的安全性，对象存储和图片存储
2. 禁止将文件存储在web应用程序目录。
3. 必须依据实际业务需求使用白名单策略限制上传文件后缀名。
4. 禁止上传html、htm、 swf 等可被浏览器解析的文件。
5. 禁止将用户可控的内容上传至京东域名。


#### 跨站请求伪造简介 （CSRF）

##### 简介
CSRF(Cross-site request forgery),攻击者利用受害者身份发起http请求，在用户不知情的情况下进行业务操作。

跨域攻击原理，举例说明：Web A为存在CSRF漏洞的网站，Web B为攻击者构建的恶意网站，User C为Web A网站的合法用户。

1. 用户C打开浏览器，访问受信任网站A，输入用户名和密码请求登录网站A；

2. 在用户信息通过验证后，网站A产生Cookie信息并返回给浏览器，此时用户登录网站A成功，可以正常发送请求到网站A；

3. 用户未退出网站A之前，在同一浏览器中，打开一个TAB页访问网站B；

4. 网站B接收到用户请求后，返回一些攻击性代码，并发出一个请求要求访问第三方站点A；

5. 浏览器在接收到这些攻击性代码后，根据网站B的请求，在用户不知情的情况下携带Cookie信息，向网站A发出请求。网站A并不知道该请求其实是由B发起的，所以会根据用户C的Cookie信息以C的权限处理该请求，导致来自网站B的恶意代码被执行。

##### 攻击防御
1.验证http refer 字段
refer 字段记录了http请求的来源地址。验证refer字段是否属于当前网站，如果refer 来源于其他网站，可拒绝该请求。

1）验证Referer是否来自jd.com（适用场景：处理单一请求）
```
import java.net.URL;// 从HTTP头中取得Referer值
URL referer = new URL(request.getHeader("Referer"));
String host = referer.getHost();// 判断Referer是否符合规则
if((subDomain!=null) && host.endsWith(".jd.com"))
{// 正常处理业务请求}
else
{// 拒绝处理业务请求}
```


2）验证Referer是否来自特定的三（四）级域名（如只允许search.jd.com）
```
// 从HTTP头中取得Referer值URL 
referer = new URL(request.getHeader("Referer"));
String host = referer.getHost();// 判断Referer是否符合规则
if((host!=null) && host.equals("search.jd.com")){
// 正常处理业务请求
    
}
else{// 拒绝处理业务请求
    
}
```

2.在业务请求中添加token并验证实现步骤如下:

1).用户登录成功业务系统后，随机生成一个CSRF的token，同时将token设置在用户cookie中，当用户退出或浏览器关闭时，清除token。

2). 在表单中，生成一个隐藏域（通常是一个hidden input）,它的值为cookie中的随机token。



#### JSONP漏洞
##### 什么是JSONP
JSONP 是服务端与客户端跨源通信的常用办法，基本思想是，网页通过添加一个<script>元素，向服务器请求json数据，这种做法不受同源政策限制。服务器收到请求后，将数据放在一个指定名字的回调函数中传回来。JSONp 只能发送get请求

##### JSONP 安全编码
JSONP 的跨域传输数据，必须验证JSON请求来源为jd域或者定义白名单域名。


####  CORS漏洞
##### 什么是CORS 
cors 是跨资源分享的缩写，是解决ajax 跨域的根本解决办法。
CORS 允许浏览器向跨源服务器，发出xmlHttpRequest 请求，从而克服了ajax 只能同源的限制。
CORS 通信的关键在服务器，只要服务器实现了CORS接口，就可以跨源通信。

##### CORS 请求说明
浏览器将CORS请求分为两种类型，简单请求和非简单请求
###### 简单请求
简单请求需要满足以下条件：
（1) 请求方法是以下三种方法之一：
HEAD
GET
POST
（2）HTTP的头信息不超出以下几种字段：
Accept
Accept-Language
Content-Language
Last-Event-ID
Content-Type：只限于三个值application/x-www-form-urlencoded、multipart/form-data、text/plain

###### 简单请求处理
简单请求，浏览器直接发出CORS请求，具体来说，就是在头信息中，添加一个origin 字段，用于说明本次请求来自于哪个源，服务器根据这个值，决定是否同意本次请求。

如果origin 指定的域名在许可范围内，服务器响应会多出几个头信息字段

```
Access-Control-Allow-Origin: http://api.bob.com   //必须字段，*代表接受任意域名请求
Access-Control-Allow-Credentials: true          //可选字段，标识是否允许发送cookie. 默认请求下不发送cookie。
Access-Control-Expose-Headers: FooBar        //XMLHttpRequest对象的getResponseHeader()方法只能拿到6个基本字段：Cache-Control、Content-Language、Content-Type、Expires、Last-Modifie                                             // d、Pragma。如果想拿到其他字段，就必须在Access-Control-Expose-Headers里面指定。
Content-Type: text/html; charset=utf-8

```
如果需要发送cookie，开发者必须在ajax请求中打开withCredentials 属性。
```
var xhr = new XMLHttpRequest();
xhr.withCredentials = true;
```
如果要发送Cookie，Access-Control-Allow-Origin就不能设为星号，必须指定明确的、与请求网页一致的域名。同时，Cookie依然遵循同源政策，只有用服务器域名设置的Cookie才会上传，其他域名的Cookie并不会上传，且（跨源）原网页代码中的document.cookie也无法读取服务器域名下的Cookie。


##### 安全规范
1. 当业务存在跨域需求时，需要设置access-control-allow-origin 及origin 白名单域名
2. 当跨域请求需要携带cookie时，才允许设置Access-Contorl-Allow-Credentials 头，并且必须设置精细化的白名单。例如，*.jd.com必须禁止
3. 需要跨域是，设置origin白名单，只允许特定域发起跨域请求；若不需要cookie，则不设置。


#### SSRF漏洞
##### 简介
SSRF 服务端请求伪造，是通过攻击者构造的由服务端发起的请求的安全漏洞。SSRF攻击目标通常是从外网无法访问的内部系统。
形成的主要原因是，由于服务器提供了从其他服务器应用获取数据的功能且没有对目标地址做过滤和限制。比如从指定的url地址获取网页文本内容，加载指定地址的图片。

##### 漏洞危害
1.扫描内外部网络
2.向内外部主机的发送精心构造的数据包
3.DOS（如：请求大文件，始终保持连接）

##### 安全原则
1.必须使用白名单策略限制请求地址协议，原则上仅允许http、https协议。
2.必须使用白名单策略限制请求地址端口，原则上仅允许80、443等常规端口。
3.强烈建议使用白名单策略限制请求地址域名或IP地址，禁止使用*.jd.com等通配域名。
4.禁止请求地址可解析到内网地址。
5.禁用301、302等重定向。


#### URL 跳转漏洞
##### 简介
Web业务系统接收到用户提交的URL参数后，未对URL参数进行“可信URL校验，就向用户浏览器返回跳转到该不可信URL。 如果jd.com下某个Web业务系统存在URL跳转漏洞，攻击者向用户发送一个存在URL跳转的链接，该链接跳转到钓鱼网站页面，可能会导致用户被钓鱼攻击。

##### 安全编码
判断用户传入的URL参数是否为jd域URL



#### SQL注入
##### 简介
当应用程序直接将输入内容拼接到sql语句中时，攻击者可以通过自定义语句来改变sql逻辑，特定情况下可以获取到数据库的数据及数据库服务器的系统权限
注入需要两个条件：1. 用户可以控制输入，2 程序要执行的代码拼接了用户输入数据。

举个栗子:)
当用户发送GET请求：http://www.xxx.com/news.jsp?id=1
这是一个新闻详情页面，会显示出新闻的title和content，程序内部会接收这个id参数传递给SQL语句，

SQL如下：
```
SELECT title,contentFROM news WHERE id = 1
```
这是SQL的原义,也是程序员想要得到的结果,但是如果用户改变了id的内容，修改成如下：
http://www.jd.com/news.jsp?id=1  and  1=2  UNION  SELECT  userna-me,  password  FROM  admin 
此时内部程序执行的SQL语句为：
```
SELECT  title,contentFROM  news  WHERE  id  =  1  and  1=2  UNION SELECT username, password FROM admin
```
这条SQL的原义就会被改变，导致将管理员数据表中的用户名显示在页面title位置，密码显示在页面content位置，攻击成功。

可以采用jdbc 预编译方式来解决这个问题
```
select * from news where id=#{id}
```
这种写法可以很好地避免SQL注入


注入类型分为以下几种：
1. 布尔型注入
2. 报错型注入
3. 联合查询注入
4. 多语句查询注入
5. 基于时间延时注入


##### mybatis易产生sql注入漏洞场景分析

1. 模糊查询like

如果考虑安全编码规范问题，其对应的SQL语句如下：
```
Select * from news where titlelike ‘%#{title}%’，
```
但由于这样写程序会报错，研发人员将SQL查询语句修改如下：
```
Select * from newswhere titlelike ‘%${title}%
```
，在这种情况下我们发现程序不再报错，但是此时产生了SQL语句拼接问题，如果java代码层面没有对用户输入的内容做处理势必会产生SQL注入漏洞。


2. in之后的参数

在对新闻进行同条件多值查询的时候，如当用户输入1001,1002,1003...100N时，如果考虑安全编码规范问题，其对应的SQL语句如下：
```
Select * from news where id in (#{id})
```
但由于这样写程序会报错，研发人员将SQL查询语句修改如下：
```
Select * from news where id in (${id})
```
修改SQL语句之后，程序停止报错，但是却引入了SQL语句拼接的问题，如果研发人员没有对用户输入的内容做过滤，势必会产生SQL注入漏洞。


3. 3order by之后

当根据发布时间、点击量等信息对新闻进行排序的时候，如果考虑安全编码规范问题，其对应的SQL语句如下：
```
Select * from news where title=‘京东’order by #{time} asc
```
但由于发布时间time不是用户输入的参数，无法使用预编译。研发人员将SQL查询语句修改如下：
```
Select * from news where title=‘京东’order by ${time} asc
```
修改之后，程序通过预编译，但是产生了SQL语句拼接问题，极有可能引发SQL注入漏洞。



##### 注入漏洞修复方法
1. 模糊查询like 

SQL注入修复建议按照新闻标题对新闻进行模糊查询，可将SQL查询语句设计如下：
```
select * from news where tilelike concat(‘%’,#{title}, ‘%’)
```
采用预编译机制，避免了SQL语句拼接的问题，从根源上防止了SQL注入漏洞的产生

2. in之后的参数SQL注入修复建议
在对新闻进行同条件多值查询的时候，可使用Mybatis自带循环指令解决SQL语句动态拼接的问题
```
select * from news where id in <foreach collection="ids" item="item" open="("separator="," close=")">#{item} </foreach>
```

3. order bySQL注入修复建议--在Java层面做映射预编译机制只能处理查询参数，其他地方还需要研发人员根据具体情况来解决。
需要研发人员在代码控制层传入sql语句的参数，禁止将用户输入的数据直接传入sql中。
a. 预先order by 字段字典
b. 预定义默认排序规则


#### xxe 漏洞简介
xxe（xml external entity） xml 外部实体注入，通过构造恶意内容，可导致读取任意文件、执行系统命令、探测内网端口、攻击内网等危害。

##### 漏洞测试
在输入request 中引入xml 文本，请求服务器上资源。

##### 安全规则
通过禁用外部实体的方法来防止xxe 漏洞的产生

1）DocumentBuilderFactory禁用DTDS方法
```
DocumentBuilderFactory dbf =DocumentBuilderFactory.newInstance();//禁用DOCTYPEdbf.setExpandEntityReferences(false);
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setXIncludeAware(false);
```


2）SAXParserFactory禁用DTDS方法
```
SAXParserFactory sax=SAXParserFactory.newInstance();
sax.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
sax.setFeature("http://xml.org/sax/features/external-general-entities", false);
```

#### 命令执行漏洞



#### java 反序列化漏洞
##### 简介
序列化就是把对象转换成字节流，便于保存在内存、文件、数据库中；反序列化即逆过程，由字节流还原成对象。Java中的ObjectOutputStream类的writeObject()方法可以实现序列化，类ObjectInputStream类的readObject()方法用于反序列化

问题在于，如果java 应用对用户输入的不可信数据做了反序列化处理，那么攻击者可以通过构造恶意输入，让反序列化产生非预期对象，可能带来任意代码的执行。

##### 安全规则
使用京东的java 反序列化漏洞防护组件
本程序通过给默认的java.io.ObjectInputStream添加Class名称黑名单，防止java反序列化漏洞，程序默认自带的类黑名单(JAVA反序列化黑名单类)包含目前已知的所有可以用于构造反序列化调用方法链的类名称。

引入依赖

<dependency>
    <groupId>com.jd.security.codesec</groupId>
    <artifactId>ajdv</artifactId>
    <version>0.1</version>
</dependency>



使用方法

默认情况下，在进行Java反序列化操作时，使用如下代码，就可以防止反序列化安全漏洞：

ObjectInputStream ois = new JDSafeObjectInputStream(new FileInputStream("/tmp/xxx"));

Object o = ois.readObject();



如果需要定制黑名单可以通过如下两种方式

方法一：

自己提供类黑名单，这方式将完全替换程序默认提供的类黑名单

Set<String> classBlackList = new HashSet<String>();
classBlackList.add("com.xxx.xxx.AAA");

classBlackList.add("com.xxx.xxx.BBB");

JDSafeObjectInputStream ois = new JDSafeObjectInputStream(new FileInputStream("/tmp/xxx"),classBlackList );

Object o = ois.readObject();



方法二：

添加额外的黑名单，这种方式不会替换程序自带的黑名单，而是在原有黑名单基础之上添加额外的黑名单类

JDSafeObjectInputStream ois = new JDSafeObjectInputStream(new FileInputStream("/tmp/xxx") );

ois.addBlackList("com.xxx.xxx.AAA");

ois.addBlackList("com.xxx.xxx.BBB");

Object o = ois.readObject();




#### 安全测试工具
##### 京东自研的自动化测试工具
1. 开源组件漏洞检测平台 http://osssec.jd.com/   erp登陆
2. 源代码安全检测平台   http://jsssec.jd.com/  erp登陆
3. 黑盒扫描检测平台 http://anquan.jd.com/#/service/scanner/add
输入扫描目标、抓取域名、线程数、cookie、hosts 信息，创建任务即可。 
或者使用黑盒扫描器chrome插件
https://chrome.google.com/webstore/detail/zerologger/jacplpdffllbcnagfpgmbioihodfonfa

##### 自动化工具
AWVS --自动化的web 应用程序安全测试工具。



##### 常用的手工测试工具
用户交互是web应用的核心功能。借由分析拦截、修改、分析用户端发出的数据，可以发现多种安全风险。

数据包分析能解决的问题
1. 会话管理类漏洞
2. 代码注入类漏洞
3. 业务逻辑类漏洞
4. 暴力破解类漏洞
5. 其他如CSRF漏洞、URL重定向漏洞

数据包分析不能解决的问题:  需要发送大量请求的测试

数据抓包工具

1.BrupSuit 功能介绍

Proxy：一个代理，默认8080端口，截获从客户端到web应用程序的数据包。
- Spider：用来抓取Web应用程序的链接和内容等，它会自动提交登陆表单（通过用户自定义输入）的情况下。
- BurpSuite的蜘蛛可以爬行扫描出网站上所有的链接,。
- Scanner：用于扫描Web应用程序漏洞。
- Intruder：多种模糊测试的用途，如进行暴力猜解等.•Repeater：根据不同的情况修改和发送修改过的请求并分析


2.Fiddler

专项测试工具：
1. struts2 漏洞利用工具
2. Sql 注入类测试工具

浏览器插件测试工具
1. HackBar
2. Xss me