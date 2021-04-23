import json
import os
import time
import random
import requests
from urllib.parse import urlparse

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class WechatPayV3(object):
    def __init__(self):
        self.current_path = os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
        self.app_id = config['WEIXIN_APP_ID']  # 微信支付APP_ID
        self.partner_id = config['WEIXIN_MCH_ID']  # 商户号ID
        self.partner_key = config['WEIXIN_KEY']  # 微信支付 KEY
        self.serial_no = config['WECHAT_API_CERTIFICATE_SERIAL_NO']
        self.wechat_serial_no = config['WECHAT_CERTIFICATE_SERIAL_NO']
        self.timestamp = str(int(time.time()))
        self.nonce_str = str(random.randint(100000, 10000000))
        self.get_wechat_private_key_string()
        self.get_wechat_public_key_string()
        self.get_wechat_certificate()

    def get_wechat_private_key_string(self):
        """获取商户私钥"""
        wechat_key_path = os.path.join(self.current_path, "key", "wechat_apiclient_key.pem")
        self.private_key = open(wechat_key_path).read()

    def get_wechat_public_key_string(self):
        """获取微信公钥"""
        wechat_public_key_path = os.path.join(self.current_path, "key", "wechat_apiclient_cert.pem")
        self.public_key = open(wechat_public_key_path).read()

    def get_wechat_certificate(self):
        """微信支付平台公钥"""
        wechat_certificate_path = os.path.join(self.current_path, "key", "wechatpay_certificate.pem")
        self.wechat_certificate = open(wechat_certificate_path).read()

    def notify_verify(self, serial, timestamp, nonce, signature, json_data):
        """
        回调验签
        :param serial:平台证书序列号
        :param timestamp:应答时间戳
        :param nonce:应答随机串
        :param signature:应答签名
        :param json_data:应答主体字符串
        :return:
        """
        if serial != self.wechat_serial_no:
            return False
        sign_str = timestamp + "\n" + nonce + "\n" + json_data + "\n"
        return self.sign_verify(sign_str, signature)

    @staticmethod
    def aes_gcm_decrypt(resource):
        """解密"""
        nonce, ciphertext, associated_data = resource.get('nonce'), resource.get('ciphertext'), resource.get(
            'associated_data')
        key_bytes = str.encode(config['WECHAT_PAY_API_V3_KEY'])
        nonce_bytes = str.encode(nonce)
        ad_bytes = str.encode(associated_data)
        data = b64decode(ciphertext)

        aesgcm = AESGCM(key_bytes)
        return json.loads(aesgcm.decrypt(nonce_bytes, data, ad_bytes))

    def sign_verify(self, message, signature):
        """验签"""
        sign = b64decode(signature)
        pubkey = RSA.importKey(self.wechat_certificate)
        verifier = pkcs1_15.new(pubkey)
        rand_hash = SHA256.new()
        rand_hash.update(message.encode("utf8"))
        try:
            verifier.verify(rand_hash, sign)
        except ValueError:
            return False
        return True

    def sign_str(self, method, url_path, request_body):
        """
        生成欲签名字符串
        """
        sign_list = [
            method,
            url_path,
            self.timestamp,
            self.nonce_str,
            request_body
        ]
        return '\n'.join(sign_list) + '\n'

    def sign(self, sign_str):
        """
        生成签名
        """
        rsa_key = RSA.importKey(self.private_key)
        signer = pkcs1_15.new(rsa_key)
        digest = SHA256.new(sign_str.encode('utf8'))
        sign = b64encode(signer.sign(digest)).decode('utf8')
        return sign.replace("\n", "")

    def authorization(self, method, url_path, request_body):
        """
        生成Authorization
        """
        signstr = self.sign_str(method, url_path, request_body)
        s = self.sign(signstr)
        authorization = 'WECHATPAY2-SHA256-RSA2048 mchid="{mchid}",nonce_str="{nonce_str}",signature="{sign}",timestamp="{timestamp}",serial_no="{serial_no}"'.format(
            mchid=self.partner_id, nonce_str=self.nonce_str, sign=s, timestamp=self.timestamp, serial_no=self.serial_no)
        return authorization

    def get_wechat_order_pay_state(self, order_id):
        """
        根据商户订单号获取微信订单支付状态
        :param order_id:
        :return:
        """
        refer_order_url = 'https://api.mch.weixin.qq.com/v3/pay/transactions/out-trade-no/{out_trade_no}'.format(
            out_trade_no=order_id)
        url = urlparse(refer_order_url)
        params = {"mchid": config["WEIXIN_MCH_ID"]}
        authorization = self.authorization("GET", url.path + "?mchid={}".format(config["WEIXIN_MCH_ID"]), "")
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': authorization}
        resp = requests.get(url=refer_order_url, params=params, headers=headers)
        if resp.status_code != 200:
            return False
        return json.loads(resp.text)


class WXPayH5(WechatPayV3):
    def __init__(self, notify_url, payer_client_ip):
        super().__init__()
        self.notify_url = notify_url
        self.info_type = "iOSAndroidWap"
        self.payer_client_ip = payer_client_ip

    def h5_generate_params(self, order_no, item_name, price, attach):
        """
        获取h5支付参数
        :param order_no:订单号
        :param item_name: 商品名称
        :param price: 商品价格
        :param attach: 附加数据 string[1,128] 查询API和支付通知中原样返回
        :return:
        """
        body = {
            "appid": self.app_id,
            "mchid": self.partner_id,
            "description": item_name,
            "out_trade_no": order_no,
            "attach": attach,
            "notify_url": self.notify_url,
            "amount": {
                "total": price
            },
            "scene_info": {
                "payer_client_ip": self.payer_client_ip,
                "h5_info": {
                    "type": self.info_type
                }
            }
        }
        url = 'https://api.mch.weixin.qq.com/v3/pay/transactions/h5'
        authorization = self.authorization("POST",
                                           "/v3/pay/transactions/h5",
                                           json.dumps(body))
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': authorization}
        resp = requests.post(url=url, headers=headers, json=body)
        h5_url = json.loads(resp.text).get("h5_url")
        return h5_url

    def js_generate_params(self, order_no, item_name, price, attach, openid):
        """
        jsapi统一下单
        :param order_no:订单号
        :param item_name:商品名
        :param price:价格，分为单位
        :param attach:附加信息
        :param openid:用户微信id
        :return:
        """
        body = {
            "appid": config["WECHAT_SERVICE_APP_ID"],
            "mchid": self.partner_id,
            "description": item_name,
            "out_trade_no": order_no,
            "attach": attach,
            "notify_url": self.notify_url,
            "amount": {
                "total": price
            },
            "payer": {"openid": openid},
            "scene_info": {
                "payer_client_ip": self.payer_client_ip
            }
        }
        url = 'https://api.mch.weixin.qq.com/v3/pay/transactions/jsapi'
        authorization = self.authorization("POST",
                                           "/v3/pay/transactions/jsapi",
                                           json.dumps(body))
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': authorization}
        resp = requests.post(url=url, headers=headers, json=body)
        prepay_id = json.loads(resp.text).get("prepay_id")
        return prepay_id

    def sign_rsa(self, prepay_id):
        """jsapi订单签名"""
        sign_list = [
            config["WECHAT_SERVICE_APP_ID"],
            self.timestamp,
            self.nonce_str,
            "prepay_id={}".format(prepay_id)
        ]
        return '\n'.join(sign_list) + '\n'
