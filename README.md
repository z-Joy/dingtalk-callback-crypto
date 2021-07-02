# dingtalk-callback-crypto
钉钉事件订阅回调加解密

### 核心 APIs([钉钉参考文档](https://developers.dingtalk.com/document/app/configure-event-subcription)):
  - getEncryptedRes 解密
  - getDecryptedRes 返回success加密结果

### Example
- 返回success加密

```javascript
const callbackCrypto = new DingCallbackCrypto(TOKEN,ENCODING_AES_KEY, CORP_ID);

callbackCrypto.getEncryptedRes('success', data.timestamp, data.nonce);
```

- 解密

```
const callbackCrypto = new DingCallbackCrypto(TOKEN,ENCODING_AES_KEY, CORP_ID);

callbackCrypto.getDecryptedRes(encrypto);
```