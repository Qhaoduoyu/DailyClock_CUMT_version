import random, math, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import re, time
import requests, json
import HackRequests, yaml


timestamp = lambda:int(round(time.time() * 1000))

def encryptPassword(password, key):
    # password 加密, 该段代码参考于 https://github.com/EdenLin-c/CPdaily/blob/master/Jin.py
    def randomString(len):
        retStr = ''
        i=0
        while i < len:
            retStr += aes_chars[(math.floor(random.random() * aes_chars_len))]
            i=i+1
        return retStr

    def add_to_16(s):
        while len(s) % 16 != 0:
            s += '\0'
        return str.encode(s,'utf-8')

    def getAesString(data,key,iv):
        key = re.sub('/(^\s+)|(\s+$)/g', '', key)
        aes = AES.new(str.encode(key),AES.MODE_CBC,str.encode(iv))
        pad_pkcs7 = pad(data.encode('utf-8'), AES.block_size, style='pkcs7')
        encrypted =aes.encrypt(pad_pkcs7)
        return str(base64.b64encode(encrypted),'utf-8')
    aes_chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
    aes_chars_len = len(aes_chars)
    encrypted = getAesString(randomString(64) + password, key, randomString(16))
    return encrypted


def authServerUrl():
    # 获取 cumt.campusphere.net 认证访问地址
    url = 'https://cumt.campusphere.net/iap/login?service=https%3A%2F%2Fcumt.campusphere.net%2Fportal%2Flogin'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36 Edg/93.0.961.52',
        'Accept-Encoding': 'gzip, deflate',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
    }
    try:
        response = requests.get(url, headers=headers, allow_redirects=False)
        url = response.headers['Location'] # 改为 campusphere 跳转的认证地址
        return url
    except Exception as e:
        print('Error: authServerUrl', e, response.headers)
        return ''


def parseDate(session, url, password):
    # 获取 execution 以用于身份验证
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36 Edg/93.0.961.52'
    }
    try:
        response = session.get(url, headers=headers)
        response = session.get(url, headers=headers)
        responseText = response.text
        execution = re.findall(r'name="execution" value="(.{5361})"', responseText)[0]
        pwdEncryptSalt = re.findall(r'id="pwdEncryptSalt" value="(.{16})"', responseText)[0]
        password = encryptPassword(password, pwdEncryptSalt)
        print('[*] password, execution', password, execution)
        return session, password, execution
    except Exception as e:
        print('Error: parseDate', e, responseText)
        return '', '', ''


def login(session, url, username, password, execution):
    # 登录网站, 获得 CASTGC 等 信息, return session url cookie
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36 Edg/93.0.961.52'
    }
    data = {
        'username' : username,
        'password' : password,
        'captcha'  : '',
        '_eventId' : 'submit',
        'cllt'     : 'userNameLogin',
        'lt'       : '',
        'execution': execution
    }
    try:
        res = session.post(url, data=data, headers=headers, allow_redirects=False)
        url = res.headers['Location']
        return session, url, res.headers['Set-Cookie']
    except Exception as e:
        print('Error: login', e, res.headers)
        return '', '', ''


def getAuth(session, url, cookie):
    # 利用 CASTGC 进行再获得 campusphere 授权 return Cookie
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36 Edg/93.0.961.52',
        'Cookie': cookie
    }
    try:
        res = session.get(url, headers=headers, allow_redirects=False)
        # 获取 HWWAFSESTIME HWWAFSESID MOD_AUTH_CAS
        url = res.headers['Location']
        res = session.get(url, headers=headers, allow_redirects=False)
        Cookie = res.headers['Set-Cookie']
        print('[*] Cookie:', Cookie)
        return Cookie
    except Exception as e:
        print('Error: getAuth', e, res.headers)
        return ''


def getWid(Cookie):
    # 利用授权后的Cookie来 获取 formWid, collectorWid,以用于提交表单
    hack = HackRequests.hackRequests()
    postData = json.dumps({'pageNumber':1})
    postDataLen = len(postData)
    raw = '''
POST /wec-counselor-collector-apps/stu/collector/queryCollectorProcessingList HTTP/1.1
Host: cumt.campusphere.net
Cookie: {0}
Content-Type: application/json;charset=utf-8
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 (4480048640)cpdaily/9.0.12  wisedu/9.0.12
Content-Length: {1}
Connection: close

{2}'''.format(Cookie, postDataLen, postData)
    try:
        hh = hack.httpraw(raw=raw, ssl=True)
        searchWidJson = json.loads(hh.text())
        formWid = searchWidJson['datas']['rows'][0]['formWid']
        collectorWid = searchWidJson['datas']['rows'][0]['wid']
        return hack, formWid, collectorWid
    except Exception as e:
        print('Error :getWid\n', e, hh.text())
        return '', '', ''


def getForm(Cookie, hack, formWid, collectorWid):
    # 获得 需要填写的表单,其中有表单号等信息
    postData =  json.dumps({'pageNumber': 1, 'pageSize': 9999, 'formWid': formWid, 'collectorWid': collectorWid})
    postDataLen = len(postData)
    raw = '''POST /wec-counselor-collector-apps/stu/collector/getFormFields HTTP/1.1
Host: cumt.campusphere.net
Cookie: {0}
Content-Type: application/json;charset=utf-8
Accept: application/json, text/plain, */*
X-Requested-With: XMLHttpRequest
Accept-Language: zh-CN,zh-Hans;q=0.9
Accept-Encoding: gzip, deflate
Origin: https://cumt.campusphere.net
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 (4480048640)cpdaily/9.0.12  wisedu/9.0.12
Referer: https://cumt.campusphere.net/wec-counselor-collector-apps/stu/mobile/index.html?collectorWid=74639&from=push&v=1632646649
Content-Length: {1}
Connection: close

{2}'''.format(Cookie, postDataLen, postData)
    # print(raw)
    try:
        hh = hack.httpraw(raw=raw, ssl=True)
        formJson = json.loads(hh.text())
        return formJson
    except Exception as e:
        print('Error: getForm\n', e, hh.text())
        return ''


def getSchoolTaskWid(collectorWid, Cookie, hack):
    # 获得 schoolTaskWid, 同样用于 填写表单
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
    try:
        hh = hack.httpraw(raw=raw, ssl=True)
        tmpformJson = json.loads(hh.text())
        schoolTaskWid = tmpformJson['datas']['collector']['schoolTaskWid']
        return schoolTaskWid
    except:
        return ''


def generateForm(formJson, formWid, collectorWid, schoolTaskWid):
    # 根据需要生成新的 需填写表单
    ## 读取 配置表单
    try:
        configFile = open(r'./config.yml', encoding='utf-8')
        configForm = yaml.load(configFile)
    except:
        return ''

    ## 根据 formWid collectorWid formJson(最主要) schoolTaskWid 来修改 configForm 数据 
    configForm['form'] = formJson['datas']['rows']
    configForm['formWid']=  formWid
    configForm['collectWid'] = collectorWid
    configForm['schoolTaskWid'] = schoolTaskWid

    ## 手动填写 在风暴中哭泣😥

    ### 你的学生类别  本科生
    configForm['form'][0]['fieldItems'][0]['isSelected'] = 1
    configForm['form'][0]['value'] = configForm['form'][0]['fieldItems'][0]['itemWid']
    configForm['form'][0]['show'] = True
    configForm['form'][0]['formType'] = '0'
    configForm['form'][0]['sortNum'] = '1'
    configForm['form'][0]['logicShowConfig'] = {}
    #### 清空多余选项
    del configForm['form'][0]['fieldItems'][1]
    del configForm['form'][0]['fieldItems'][1]
    ### 你的生源地 内地
    configForm['form'][1]['fieldItems'][0]['isSelected'] = 1
    configForm['form'][1]['value'] = configForm['form'][1]['fieldItems'][0]['itemWid']
    configForm['form'][1]['show'] = True
    configForm['form'][1]['formType'] = '0'
    configForm['form'][1]['sortNum'] = '2'
    configForm['form'][1]['logicShowConfig'] = {}
    #### 清空多余选项
    del configForm['form'][1]['fieldItems'][1]
    del configForm['form'][1]['fieldItems'][1]
    ### 你今天晨检体温是多少 36~37.2℃（正常体温）
    configForm['form'][2]['fieldItems'][0]['isSelected'] = 1
    configForm['form'][2]['value'] = configForm['form'][2]['fieldItems'][0]['itemWid']
    configForm['form'][2]['show'] = True
    configForm['form'][2]['formType'] = '0'
    configForm['form'][2]['sortNum'] = '3'
    configForm['form'][2]['logicShowConfig'] = {}
    #### 清空多余选项
    del configForm['form'][2]['fieldItems'][1]
    del configForm['form'][2]['fieldItems'][1]
    ### 你今天午检体温是多少 36~37.2℃（正常体温）
    configForm['form'][3]['fieldItems'][0]['isSelected'] = 1
    configForm['form'][3]['value'] = configForm['form'][3]['fieldItems'][0]['itemWid']
    configForm['form'][3]['show'] = True
    configForm['form'][3]['formType'] = '0'
    configForm['form'][3]['sortNum'] = '4'
    configForm['form'][3]['logicShowConfig'] = {}
    #### 清空多余选项
    del configForm['form'][3]['fieldItems'][1]
    del configForm['form'][3]['fieldItems'][1]
    ### 你今天是为疑似/确诊新冠肺炎患者？ 否
    configForm['form'][4]['fieldItems'][0]['isSelected'] = 1
    configForm['form'][4]['value'] = configForm['form'][4]['fieldItems'][0]['itemWid']
    configForm['form'][4]['show'] = True
    configForm['form'][4]['formType'] = '0'
    configForm['form'][4]['sortNum'] = '5'
    configForm['form'][4]['logicShowConfig'] = {}
    #### 清空多余选项
    del configForm['form'][4]['fieldItems'][1]
    ### 你今天是否与疑似/确诊新冠肺炎患者有密切接触？ 否
    configForm['form'][5]['fieldItems'][0]['isSelected'] = 1
    configForm['form'][5]['value'] = configForm['form'][5]['fieldItems'][0]['itemWid']
    configForm['form'][5]['show'] = True
    configForm['form'][5]['formType'] = '0'
    configForm['form'][5]['sortNum'] = '6'
    configForm['form'][5]['logicShowConfig'] = {}
    #### 清空多余选项
    del configForm['form'][5]['fieldItems'][1]
    ### 你今天是否有咳嗽、乏力等症状 否
    configForm['form'][6]['fieldItems'][0]['isSelected'] = 1
    configForm['form'][6]['value'] = configForm['form'][6]['fieldItems'][0]['itemWid']
    configForm['form'][6]['show'] = True
    configForm['form'][6]['formType'] = '0'
    configForm['form'][6]['sortNum'] = '7'
    configForm['form'][6]['logicShowConfig'] = {}
    #### 清空多余选项
    del configForm['form'][6]['fieldItems'][1]
    ### 你今天是否就诊或住院 否
    configForm['form'][7]['fieldItems'][0]['isSelected'] = 1
    configForm['form'][7]['value'] = configForm['form'][7]['fieldItems'][0]['itemWid']
    configForm['form'][7]['show'] = True
    configForm['form'][7]['formType'] = '0'
    configForm['form'][7]['sortNum'] = '8'
    configForm['form'][7]['logicShowConfig'] = {}
    #### 清空多余选项
    del configForm['form'][7]['fieldItems'][1]
    del configForm['form'][7]['fieldItems'][1]
    ### 如果就诊或住院，请填写你去的医院名称（注：未就诊、住院的不填） 否,不填
    configForm['form'][8]['show'] = True
    configForm['form'][8]['formType'] = '0'
    configForm['form'][8]['sortNum'] = '9'
    configForm['form'][8]['logicShowConfig'] = {}
    ### 你是否被隔离，如果被隔离，请选择你的隔离方式 否
    configForm['form'][9]['fieldItems'][0]['isSelected'] = 1
    configForm['form'][9]['value'] = configForm['form'][9]['fieldItems'][0]['itemWid']
    configForm['form'][9]['show'] = True
    configForm['form'][9]['formType'] = '0'
    configForm['form'][9]['sortNum'] = '10'
    configForm['form'][9]['logicShowConfig'] = {}
    #### 清空多余选项
    del configForm['form'][9]['fieldItems'][1]
    del configForm['form'][9]['fieldItems'][1]
    ### 如果被隔离，请填写目前被隔离的详细地址（注：未被隔离的不填） 未隔离
    configForm['form'][10]['show'] = True
    configForm['form'][10]['formType'] = '0'
    configForm['form'][10]['sortNum'] = '11'
    configForm['form'][10]['logicShowConfig'] = {}
    ### 目前是否在学校 是
    configForm['form'][11]['fieldItems'][0]['isSelected'] = 1
    configForm['form'][11]['value'] = configForm['form'][11]['fieldItems'][0]['itemWid']
    configForm['form'][11]['show'] = True
    configForm['form'][11]['formType'] = '0'
    configForm['form'][11]['sortNum'] = '12'
    configForm['form'][11]['logicShowConfig'] = {}
    #### 清空多余选项
    del configForm['form'][11]['fieldItems'][1]
    ### 目前你所在城市 '江苏省/徐州市/铜山区/
    configForm['form'][12]['value'] = '江苏省/徐州市/铜山区/'
    configForm['form'][12]['show'] = True
    configForm['form'][12]['formType'] = '0'
    configForm['form'][12]['sortNum'] = '13'
    configForm['form'][12]['logicShowConfig'] = {}
    ### 今天是否有跨区域行程异动（注：指跨县及以上行政区域，徐州市内各区之间的交通活动不用填报） 否
    configForm['form'][13]['fieldItems'][0]['isSelected'] = 1
    configForm['form'][13]['value'] = configForm['form'][13]['fieldItems'][0]['itemWid']
    configForm['form'][13]['show'] = True
    configForm['form'][13]['formType'] = '0'
    configForm['form'][13]['sortNum'] = '14'
    configForm['form'][13]['logicShowConfig'] = {}
    #### 清空多余选项
    del configForm['form'][13]['fieldItems'][1]
    ### 如果行程有异动，请填写异动具体时间（注：未异动的不填）否
    configForm['form'][14]['show'] = True
    configForm['form'][14]['formType'] = '0'
    configForm['form'][14]['sortNum'] = '15'
    configForm['form'][14]['logicShowConfig'] = {}
    ### 如果行程有异动，请填写行程异动目的地（注：未异动的不填）否
    configForm['form'][15]['show'] = True
    configForm['form'][15]['formType'] = '0'
    configForm['form'][15]['sortNum'] = '16'
    configForm['form'][15]['logicShowConfig'] = {}
    ### 如果行程有异动，请填写异动原因、出行方式和具体车次等信息（未异动的不填） 否
    configForm['form'][16]['show'] = True
    configForm['form'][16]['formType'] = '0'
    configForm['form'][16]['sortNum'] = '17'
    configForm['form'][16]['logicShowConfig'] = {}
    ### 本人是否承诺以上所填报的全部内容属实、准确，不存在任何隐瞒、不实和遗漏之处 确定
    configForm['form'][17]['value'] = configForm['form'][17]['fieldItems'][0]['itemWid']
    configForm['form'][17]['show'] = True
    configForm['form'][17]['formType'] = '0'
    configForm['form'][17]['sortNum'] = '18'
    configForm['form'][17]['logicShowConfig'] = {}
    #### 清空多余选项
    del configForm['form'][17]['fieldItems'][1]
    ## 添加末尾信息
    configForm['uaIsCpadaily'] = True
    configForm['latitude'] = 34.214014
    configForm['latitude'] = 117.145081
    # 返回 表单
    return configForm


def submitForm(configForm, Cookie, hack):
    postData = json.dumps(configForm)
    postDataLen = len(postData)
    raw = '''
POST /wec-counselor-collector-apps/stu/collector/submitForm HTTP/1.1
Host: cumt.campusphere.net
Cookie: {0}
Accept: */*
Content-Type: application/json
Cpdaily-Extension: 64JITpWPkKtUkPOlKP1yHfWAD+jUF0R5Cx/ou+A4jqUqgWk7tzyzDVcXPd/Q 6b3Ien3x11uqd6I/v+S3etP2SauWgaBNYAbwm8xTx3/HDdRGIQmLI+LfMfLc RuFLj7aPuXtiBBgg+3gSVLI8SYZF7VLQcSEV9UFxu8iS6Xw5ZDkxuAcyZvhB NrWy9lbutL1uIEGlnT6weUghFysWTxk2hWkgWWXaPWRxkhftB88X2lflLLKd SJHku1KvHa+faogGiDIkWzrOrJVvPPnUkdnBcg==
Accept-Language: zh-cn
Content-Length: {1}
Accept-Encoding: gzip, deflate
Connection: close

{2}'''.format(Cookie, postDataLen, postData)
    # print(raw)
    try:
        hh = hack.httpraw(raw=raw, ssl=True)
        return hh
    except:
        return ''


def main(username, password):
    session = requests.Session()
    url = authServerUrl()
    session, password, execution = parseDate(session, url, password)
    session, url, cookie = login(session, url, username, password, execution)
    Cookie = getAuth(session, url, cookie)
    hack, formWid, collectorWid = getWid(Cookie)
    formJson = getForm(Cookie, hack, formWid, collectorWid)
    schoolTaskWid = getSchoolTaskWid(collectorWid, Cookie, hack)
    configForm = generateForm(formJson, formWid, collectorWid, schoolTaskWid)
    hh = submitForm(configForm, Cookie, hack)
    if hh == '':
        print('提交失败')
    else:
        print(hh.text())


if __name__ == '__main__':
    # 账户为  http://authserver.cumt.edu.cn/authserver/login 账户
    username = ''
    password = ''
    main(username, password)