ghopenbiz
===
# 招商银行银企直连 
```go
// 首先要获取配置,构造请求数据

import (
"github.com/guihai/ghopenbiz/cmbc"
)

sm := cmbc.SMTool{}

// 1,请求数据签名
sm.SignString(uid, prikey, data)

// 2,签名后的数据加密
sm.EncryptByString(uid, ukey, data)
// 3,发送请求
post()
// 4，获取响应解密
sm.DecryptByString(uid, ukey, res)

// 5，数据验签
sm.VerifyString(uid, pubk, back, backSigin)
```