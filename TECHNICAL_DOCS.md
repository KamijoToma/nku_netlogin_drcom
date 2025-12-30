# 南开大学校园网认证系统 (Dr.COM/ePortal) 技术文档

## 1. 系统概况
- **认证地址**: `https://netauth.nankai.edu.cn:804/eportal/portal/login`
- **检测机制**: 访问 HTTP 网站（如 `http://www.baidu.com`）会触发 302 重定向，重定向 URL 中包含认证所需的关键参数。

## 2. 关键参数获取
通过捕获 HTTP 重定向 URL，可以解析出以下参数：
- `wlanuserip`: 用户 IP 地址
- `wlanacname`: AC 设备名称 (例如 `NKU-WLAN-Core`)
- `wlanacip`: AC 设备 IP
- `nasip`: NAS IP
- `ssid`: 网络 SSID (如 `NKU_WLAN`)
- `mac`: 用户 MAC 地址 (部分情况下可能为空或全 0)

## 3. 登录接口详情
- **URL**: `https://netauth.nankai.edu.cn:804/eportal/portal/login`
- **Method**: GET (JSONP)
- **Query Parameters**:
    - `callback`: JSONP 回调函数名 (如 `dr1003`)
    - `login_method`: `1`
    - `user_account`: `drcom`
    - `user_password`: (加密后的密码)
    - `wlan_user_ip`: (从重定向获取)
    - `wlan_user_ipv6`: (可选)
    - `wlan_user_mac`: (从重定向获取，或全0)
    - `wlan_ac_ip`: (可选)
    - `wlan_ac_name`: (可选)
    - `jsVersion`: `2.4.3` (或其他版本号)

## 4. 密码加密算法
密码采用自定义的 XOR 加密算法。

### 算法逻辑
1. **密钥生成**: 
   - 基础字符串: `"drcom"`
   - 密钥: `119` (即 `0x77`)。
   - *注: 原始 JS 逻辑中可能包含更复杂的密钥生成，但在当前环境下，密钥固定为 119。*

2. **加密过程**:
   - 遍历密码字符串的每个字符。
   - 将字符的 ASCII 码与密钥进行 XOR 运算。
   - 结果即为加密后的字符代码。
   - 最终将所有字符代码拼接（通常不需要转 Hex，直接作为 URL 参数值，但在 Python 请求中可能需要注意编码）。
   - *实际抓包观察*: 加密后的密码通常是一串数字或特定字符序列。根据之前的逆向，算法如下：
     ```python
     def enc_pwd(password):
         key = 119 # 'w'
         return "".join([chr(ord(c) ^ key) for c in password])
     ```

## 5. 登出 (Logout) 接口
通过分析抓包数据 (`logout.sh`)，发现登出接口要求**所有关键参数都必须经过 XOR 加密**，且包含 `encrypt=1` 参数。

- **URL**: `https://netauth.nankai.edu.cn:804/eportal/portal/login` (注意：虽然是 logout 操作，但抓包显示路径可能为 `portal/logout`，需确认。脚本中使用的是 `portal/logout`)
- **URL (修正)**: `https://netauth.nankai.edu.cn:804/eportal/portal/logout`
- **Method**: GET
- **Query Parameters** (需加密的参数):
    - `callback`: `dr1004` (或其他回调名) -> 加密
    - `login_method`: `1` -> 加密
    - `user_account`: 用户名 (如 `drcom` 或学号) -> 加密
    - `user_password`: `123` (或任意值) -> 加密
    - `ac_logout`: `1` -> 加密
    - `register_mode`: `1` -> 加密
    - `wlan_user_ip`: 用户 IP -> 加密
    - `wlan_user_ipv6`: (空) -> 加密
    - `wlan_vlan_id`: `1` -> 加密
    - `wlan_user_mac`: 用户 MAC -> 加密
    - `wlan_ac_ip`: (空) -> 加密
    - `wlan_ac_name`: (空) -> 加密
    - `jsVersion`: `4.3` -> 加密

- **Query Parameters** (不加密的参数):
    - `encrypt`: `1`
    - `v`: 时间戳或随机数
    - `lang`: `zh`

## 6. 流程总结
1. **探测**: 发送 HTTP 请求至公网 IP，捕获 302 Location。
2. **解析**: 从 Location URL 中提取 `wlanuserip` 等参数。
3. **加密**: 使用 XOR 算法加密用户密码。
4. **登录**: 构造带参数的 GET 请求访问登录接口。
5. **验证**: 检查返回的 JSON 响应，`result: 1` 表示成功。
6. **登出**: 
   - 获取当前 IP 和用户名 (通过探测或访问账户页)。
   - 构造包含所有必要参数的字典。
   - 对字典中除 `encrypt`, `v`, `lang` 外的所有值进行 XOR 加密。
   - 发送请求至 `portal/logout` 接口。
   - 检查返回的 `{"result":1,"msg":"Radius注销成功！"}`。

