#!/usr/bin/env python3
"""
企业微信消息回调中间服务（Flask）

功能：
1. 接收企业微信消息回调（支持 URL 验证和消息解密）
2. 解密消息内容，转发给 ADP Skill 处理
3. 接收 Skill 处理结果，推送反馈给用户
4. 提供每日提醒触发端点
"""

import os
import json
import logging
import hashlib
import base64
import struct
import socket
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from flask import Flask, request, jsonify

# 尝试导入加密库
try:
    from Crypto.Cipher import AES
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("警告: pycryptodome 未安装，消息解密功能不可用。请运行: pip install pycryptodome")

# ---------- 配置 ----------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# 从环境变量读取配置
WECOM_CORPID = os.environ.get('WECOM_CORPID', '')
WECOM_SECRET = os.environ.get('WECOM_SECRET', '')
WECOM_AGENTID = os.environ.get('WECOM_AGENTID', '')
WECOM_TOKEN = os.environ.get('WECOM_TOKEN', '')
WECOM_ENCODING_AES_KEY = os.environ.get('WECOM_ENCODING_AES_KEY', '')
TENCENT_DOC_BOOK_ID = os.environ.get('TENCENT_DOC_BOOK_ID', '')
TENCENT_DOC_SHEET_ID = os.environ.get('TENCENT_DOC_SHEET_ID', '')
TARGET_USER_ID = os.environ.get('TARGET_USER_ID', '')
WEBHOOK_HOST = os.environ.get('WEBHOOK_HOST', '0.0.0.0')
# Railway 使用 PORT 环境变量
WEBHOOK_PORT = int(os.environ.get('PORT', os.environ.get('WEBHOOK_PORT', '8080')))


# ---------- 企业微信消息加解密 ----------
class WXBizMsgCrypt:
    """企业微信消息加解密工具类"""

    def __init__(self, token, encoding_aes_key, corp_id):
        self.token = token
        self.encoding_aes_key = encoding_aes_key
        self.corp_id = corp_id
        self.aes_key = base64.b64decode(encoding_aes_key + "=")

    def verify_url(self, msg_signature, timestamp, nonce, echostr):
        """验证 URL 有效性"""
        sort_list = sorted([self.token, timestamp, nonce, echostr])
        sort_str = "".join(sort_list)
        signature = hashlib.sha1(sort_str.encode()).hexdigest()
        if signature != msg_signature:
            return None
        return self._decrypt(echostr)

    def decrypt_msg(self, msg_signature, timestamp, nonce, post_data):
        """解密消息"""
        xml_tree = ET.fromstring(post_data)
        encrypt = xml_tree.find("Encrypt")
        if encrypt is None:
            return None
        encrypt_text = encrypt.text

        sort_list = sorted([self.token, timestamp, nonce, encrypt_text])
        sort_str = "".join(sort_list)
        signature = hashlib.sha1(sort_str.encode()).hexdigest()
        if signature != msg_signature:
            logger.error("消息签名验证失败")
            return None

        return self._decrypt(encrypt_text)

    def _decrypt(self, text):
        """AES 解密"""
        if not HAS_CRYPTO:
            logger.error("加密库未安装，无法解密")
            return None
        try:
            cipher = AES.new(self.aes_key, AES.MODE_CBC, self.aes_key[:16])
            plain_text = cipher.decrypt(base64.b64decode(text))
            # 去除补位
            pad = plain_text[-1]
            content = plain_text[16:-pad]
            # 提取消息内容 (xml_len + msg + corp_id)
            xml_len = struct.unpack(">I", content[:4])[0]
            xml_content = content[4:4 + xml_len].decode("utf-8")
            return xml_content
        except Exception as e:
            logger.error(f"解密失败: {e}")
            return None


# 初始化加解密工具
_crypt = None
if WECOM_TOKEN and WECOM_ENCODING_AES_KEY and WECOM_CORPID:
    _crypt = WXBizMsgCrypt(WECOM_TOKEN, WECOM_ENCODING_AES_KEY, WECOM_CORPID)


# ---------- 消息解析 ----------
def parse_message(xml_content):
    """解析企业微信 XML 消息，提取关键字段"""
    try:
        root = ET.fromstring(xml_content)
        msg_type = root.find("MsgType")
        content = root.find("Content")
        from_user = root.find("FromUserName")
        to_user = root.find("ToUserName")
        create_time = root.find("CreateTime")

        return {
            "msg_type": msg_type.text if msg_type is not None else "unknown",
            "content": content.text if content is not None else "",
            "from_user": from_user.text if from_user is not None else "",
            "to_user": to_user.text if to_user is not None else "",
            "create_time": create_time.text if create_time is not None else "",
        }
    except Exception as e:
        logger.error(f"消息解析失败: {e}")
        return None


# ---------- 路由 ----------
@app.route('/health', methods=['GET'])
def health():
    """健康检查"""
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "config": {
            "wecom_configured": bool(WECOM_CORPID and WECOM_SECRET),
            "tdoc_configured": bool(TENCENT_DOC_BOOK_ID),
            "crypto_available": HAS_CRYPTO,
        }
    })


@app.route('/wecom/callback', methods=['GET', 'POST'])
def wecom_callback():
    """企业微信消息回调"""
    if _crypt is None:
        return "Crypt not configured", 500

    msg_signature = request.args.get('msg_signature', '')
    timestamp = request.args.get('timestamp', '')
    nonce = request.args.get('nonce', '')

    if request.method == 'GET':
        # URL 验证
        echostr = request.args.get('echostr', '')
        result = _crypt.verify_url(msg_signature, timestamp, nonce, echostr)
        if result:
            logger.info("URL 验证成功")
            return result
        else:
            logger.error("URL 验证失败")
            return "Verification failed", 403

    elif request.method == 'POST':
        # 接收消息
        post_data = request.data.decode('utf-8')
        xml_content = _crypt.decrypt_msg(msg_signature, timestamp, nonce, post_data)

        if xml_content is None:
            return "Decrypt failed", 400

        msg = parse_message(xml_content)
        if msg is None:
            return "Parse failed", 400

        logger.info(f"收到消息: {msg['content'][:50]}... (来自: {msg['from_user']})")

        # 这里返回空字符串，表示消息已处理
        # 实际的消息处理（信息抽取 + 表格写入 + 推送反馈）由 ADP Skill 完成
        # 中间服务在此处将消息暂存，等待 Skill 来拉取处理
        # 或者通过 HTTP 请求直接触发 ADP 处理

        # 将消息写入临时文件，供 Skill 读取
        _save_message_for_processing(msg)

        return ""


@app.route('/messages/pending', methods=['GET'])
def get_pending_messages():
    """获取待处理的消息列表（供 Skill 调用）"""
    try:
        with open('/tmp/wecom_pending_messages.json', 'r', encoding='utf-8') as f:
            messages = json.load(f)
        # 清空已读取的消息
        with open('/tmp/wecom_pending_messages.json', 'w', encoding='utf-8') as f:
            json.dump([], f)
        return jsonify({"messages": messages})
    except FileNotFoundError:
        return jsonify({"messages": []})


@app.route('/reminder', methods=['POST'])
def trigger_reminder():
    """触发每日提醒（供 cron 调用）"""
    logger.info("触发每日提醒任务")
    # 这个端点由 cron 定时调用
    # 实际提醒逻辑由 ADP Skill 完成
    # 这里返回一个信号，表示需要触发提醒
    return jsonify({
        "action": "daily_reminder",
        "timestamp": datetime.now().isoformat(),
        "book_id": TENCENT_DOC_BOOK_ID,
        "sheet_id": TENCENT_DOC_SHEET_ID,
        "target_user": TARGET_USER_ID,
    })


@app.route('/feedback', methods=['POST'])
def receive_feedback():
    """接收 ADP Skill 的处理结果反馈"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data"}), 400

    logger.info(f"收到 Skill 反馈: {data.get('action')}")

    # 通过企业微信推送反馈给用户
    if data.get('action') == 'send':
        _send_wecom_message(data.get('user_id', TARGET_USER_ID), data.get('content', ''))

    return jsonify({"status": "ok"})


# ---------- 辅助函数 ----------
def _save_message_for_processing(msg):
    """保存消息到临时文件"""
    try:
        try:
            with open('/tmp/wecom_pending_messages.json', 'r', encoding='utf-8') as f:
                messages = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            messages = []

        messages.append(msg)

        with open('/tmp/wecom_pending_messages.json', 'w', encoding='utf-8') as f:
            json.dump(messages[-100:], f, ensure_ascii=False)  # 最多保留 100 条
    except Exception as e:
        logger.error(f"保存消息失败: {e}")


def _send_wecom_message(user_id, content):
    """通过企业微信 API 发送消息"""
    # 企业微信发送消息 API
    # 这个函数由中间服务直接调用，也可以由 ADP Skill 通过连接器发送
    logger.info(f"准备发送消息给 {user_id}: {content[:50]}...")
    # 实际发送通过企业微信 API 或连接器
    # 这里仅做日志记录


# ---------- 主入口 ----------
if __name__ == '__main__':
    # Railway 使用 gunicorn 启动，不需要 app.run()
    # 这里保留用于本地测试
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)