# DailyClock-CUMT-version
>今日校园CUMT每日打卡功能。

实现脚本自动打卡功能,可自定义修改默认填报信息。

## 免责声明

**该项目只用于个人安全学习,若使用者因使用而导致的问题,本人概不负责**

## 基本原理
根据流量分析和抓包,抗大的今日校园每日打卡是利用`cumt.campusphere.net`上的打卡填写功能,同时`cumt.campusphere.net`上的学生用户认证是利用CUMT的统一身份认证平台`authserver.cumt.edu.cn/authserver/login`进行身份认证和发放凭证,最后登录到`cumt.campusphere.net`获取当日表单(每日的表单号等信息会刷新)并填写提交。
所以,从理论和实践成功的角度来说,脚本模拟打卡的条件如下:
1. `authserver.cumt.edu.cn/authserver/login` 可登录
2. `cumt.campusphere.net`已有当日的每日打卡表单,表单过期的话,是无法获取打卡表单的。

## 使用方法
所需要包
```shell
pip install requests HackRequests pyyaml pycryptodome
```
账户信息
```python
if __name__ == '__main__':
    # 账户为  http://authserver.cumt.edu.cn/authserver/login 账户
    username = ''
    password = ''
    main(username, password)
```
按要求填写 账户信息

若需要修改 打卡信息,可以自行修改 脚本中相应段落
```python
### 你的学生类别  本科生
    configForm['form'][0]['fieldItems'][0]['isSelected'] = 1
    configForm['form'][0]['value'] = configForm['form'][0]['fieldItems'][0]['itemWid']
    configForm['form'][0]['show'] = True
    configForm['form'][0]['formType'] = '0'
    configForm['form'][0]['sortNum'] = '1'
    configForm['form'][0]['logicShowConfig'] = {}
    #### 清空多余选项
    ...
    ...
    ...
    ## 添加末尾信息
    configForm['uaIsCpadaily'] = True
    configForm['latitude'] = 34.214014
    configForm['latitude'] = 117.145081
```
`config.yml`该文件,只是用于打卡表格对象的模板确定,请勿在此文件中修改!
![](http://img.xzaslxr.xyz/20210928124850.png)

## 实践过程中的一些细节和问题

### 很神奇的加密过程以及系统漏洞的可能性
#### 前端加密
`authserver.cumt.edu.cn/authserver/login`的password前端加密过程，过于离谱。
具体加密代码如下:
```javascript
function getAesString(data, key0, iv0) {
    key0 = key0.replace(/(^\s+)|(\s+$)/g, "");
    var key = CryptoJS.enc.Utf8.parse(key0);
    var iv = CryptoJS.enc.Utf8.parse(iv0);
    var encrypted = CryptoJS.AES.encrypt(data, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });
    return encrypted.toString();
}
function encryptAES(data, aesKey) {
    if (!aesKey) {
        return data;
    }
    var tmpstr = randomString(64) + data;
    var tmpiv = randomString(16);
    // console.log(tmpstr, aesKey, tmpiv);
    var encrypted = getAesString(tmpstr, aesKey, tmpiv);
    // 
    return encrypted;
}
function encryptPassword(pwd0, key) {
    try {
        return encryptAES(pwd0, key);
    } catch (e) {}
    return pwd0;
}
var $aes_chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';
var aes_chars_len = $aes_chars.length;
function randomString(len) {
    var retStr = '';
    for (i = 0; i < len; i++) {
        retStr += $aes_chars.charAt(Math.floor(Math.random() * aes_chars_len));
    }
    return retStr;
}
// encryptPassword 为加密函数,输入为 password和html中的passwordsalt
```
后端是在填充未知的情况下，如何确定用户的身份,以及execution该过程中的用途是什么,存储了什么信息。(密码学菜狗)
#### 系统漏洞的可能性
一方面,系统可能存在平行越权的可能性;另一方面`authserver.cumt.edu.cn/authserver/login`认证中的execution参数也值得注意。(看版本,没有测试)

#### 其他
另外值得一提的是
```python
    postData = json.dumps({'collectorWid': collectorWid})
    postDataLen = len(postData)
    raw = '''
POST /wec-counselor-collector-apps/stu/collector/detailCollector HTTP/1.1
Host: cumt.campusphere.net
Cookie: {0}
Content-Type: application/json;charset=utf-8
Accept: application/json, text/plain, */*
X-Requested-With: XMLHttpRequest
Accept-Language: zh-CN,zh-Hans;q=0.9
Accept-Encoding: gzip, deflate
Origin: https://cumt.campusphere.net
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 (4488202752)cpdaily/9.0.12  wisedu/9.0.12
Referer: https://cumt.campusphere.net/wec-counselor-collector-apps/stu/mobile/index.html?collectorWid=74770&from=push&v=1632718564
Content-Length: {1}
Connection: close

{2}'''.format(Cookie, postDataLen, postData)
```

该接口在设计上存在问题,只需要发送json对象和Cookie,便可以获得schoolTaskWid等参数(同样每次打卡会要求更新),接口滥用?

![image-20210928125751721](http://img.xzaslxr.xyz/20210928125752.png)

