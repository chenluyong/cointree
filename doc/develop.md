
tree 
```
bepalcoins
└─src
    ├─main
    │  └─java
    │      └─com
    │          └─bepal
    │              └─coins
    │                  ├─crypto
    │                  │  ├─ed25519
    │                  │  └─keccak
    │                  ├─keytree
    │                  │  ├─coinkey  # 添加币种[地址/公钥/私钥/签名]输出形式
    │                  │  ├─coins    # 添加币种[推导]
    │                  │  ├─config   # 币种信息[算法类型/BIP44/所属网络/主公私钥头/]
    │                  │  ├─infrastructure
    │                  │  │  ├─abstraction
    │                  │  │  ├─components
    │                  │  │  ├─coordinators
    │                  │  │  ├─derivator
    │                  │  │  ├─interfaces
    │                  │  │  ├─signer
    │                  │  │  └─tags # 添加币种标记
    │                  │  └─model
    │                  ├─models
    │                  └─utils
    └─test
        ├─java
        │  └─com
        │      └─bepal
        │          └─coins
        │              └─keytree
        └─resources

```