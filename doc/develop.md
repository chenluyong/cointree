
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
    │                  │  ├─coinkey  # 添加币种
    │                  │  ├─coins    # 添加币种
    │                  │  ├─config   # 币种信息工厂 - 需配置
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