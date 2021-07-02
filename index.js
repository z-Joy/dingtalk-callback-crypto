'use strict';
const crypto = require('crypto');

class DingCallbackCrypto {

  constructor(token, aesKey, corpIdOrAppSecret) {
    this.token = token;
    this.aesKey = aesKey;
    this.appSecret = corpIdOrAppSecret;
  }

  /**
   * 
   * @param {string} plaintext 加密明文 钉钉使用：success
   */
  generateEncrypt(plaintext) {
    const random = crypto.randomBytes(16) // 16字节的随机字符，可以不是ascii
    const msg_len = Buffer.from([0, 0, 0, plaintext.length])
    const msg = Buffer.from(plaintext, 'ascii')
    const appSecret = Buffer.from(this.appSecret, 'ascii')
    const codeStringBuffer = Buffer.concat([random, msg_len, msg, appSecret])
    const { key, iv } = this.getKeyAndIv();
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)
    let encrypted = cipher.update(codeStringBuffer, 'binary', 'base64')
    encrypted += cipher.final('base64');
    return encrypted
  }

  /**
   * 
   * @param {sting} timeStamp 当前10位的时间戳
   * @param {string} nonce 随机字符串，长度不限
   * @param {string} encrypt 新随机字符串+二进制（0007）+ success + CorpId 然后用aes-256-cbc加密，再转为Base64字符串
   * @param {sting} token 注册回调接口时设定的自定义token
   */
  generateSignature(timeStamp, nonce, encrypt, token) {
    let sortList = [timeStamp, nonce, encrypt, token];
    sortList.sort();
    let msg_signature = '';
    for (let text of sortList) {
      msg_signature += text;
    }
    const hash = crypto.createHash('sha1')
    hash.update(msg_signature)
    msg_signature = hash.digest('hex')
    return msg_signature
  }

  getKeyAndIv() {
    const aesKeyBuf = new Buffer.from(this.aesKey, 'base64')
    const key = aesKeyBuf.toString();
    const iv = key.slice(0, 16) // 偏移量
    return { key, iv };
  }

  getEncryptedRes(plaintext, timestamp, nonce) {
    if (!this.checkParamsIsUdf(plaintext, '明文不存在') && !this.checkParamsIsUdf(timestamp, '时间戳不存在') && !this.checkParamsIsUdf(nonce, '随机字符串不存在') ) {
      const encrypt = this.generateEncrypt(plaintext)
      const timeStamp = String(timestamp).slice(0, 10);
      const msg_signature = this.generateSignature(timeStamp, nonce, encrypt, this.token)
      const res = {
        msg_signature,
        timeStamp,
        nonce,
        encrypt
      }
      return res;
    }
  }

  getDecryptedRes(encrypted) {
    if (!this.checkParamsIsUdf(encrypted, '密文不存在')) {
      const { key, iv } = this.getKeyAndIv();
      const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
      decipher.setAutoPadding(false); //如果不加这个在解密钉钉加密信息的时候final()容易出错
      let decrypted = decipher.update(encrypted, 'base64');
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      const content_length = decrypted.slice(16, 20).readInt32BE(); //正文的长度，是4个字节的整数
      return decrypted.slice(20, 20 + content_length).toString('utf-8'); //通过指定长度提取出json
    }
  }

  // 检测参数是否存在
  checkParamsIsUdf(param, msg) {
    if (!param) {
      throw new Error(msg);
    }
  }
}

module.exports = DingCallbackCrypto;
