# 南开大学校园网认证系统 (Dr.COM/ePortal) 技术文档

> 以下协议均于 2026-08 在校园网 VLAN 内（LicheePi 4A 开发板）实测验证。

## 1. 系统概况
- **认证门户**: `https://netauth.nankai.edu.cn:804/eportal/portal/...`
  - 校园网内 DNS 解析到内部 AC 网关（实测 `198.18.0.7`）
  - 公网 IP `222.30.38.234` 是同一系统的对外实例（独立会话库，校园内会话不共享）
- **检测机制**: 未认证时访问任意 HTTP 网站（如 `http://www.baidu.com`）会被 302 重定向到门户；
  登出/封禁后 AC 直接丢弃 HTTP 流量（连接无响应）。
- **浏览器门户**: 门户页面（`/portal/public/pageAsset/js/a21.js` 等）的 `loadConfig`
  在服务器上存在 iconv 错误，导致浏览器页面本身无法完成配置加载——因此脚本直连 API 是可靠路径。

## 2. 本地网络信息获取
无需从重定向 URL 解析参数（重定向 query 的参数名不固定），直接本地检测：
- **IPv4**: UDP `connect()` 到 `netauth.nankai.edu.cn:804` 取源地址（不发包）
- **MAC**: `/sys/class/net/<iface>/address`（Linux），回退 `uuid.getnode()`
- **IPv6**: `ip -6 addr show` 的 global 地址（可选）
- **认证状态**: 探测 `http://www.baidu.com`（不跟随重定向）：
  `200` = 已在线；`302` = 未认证（拦截中）；连接失败 = AC 硬封禁（同样未认证）

## 3. 登录接口详情（已验证）
- **URL**: `https://netauth.nankai.edu.cn:804/eportal/portal/login`
- **Method**: GET (JSONP)
- **Query Parameters**（值均需 XOR-119-hex 加密，空值保持为空）:

| 参数 | 值 |
|------|-----|
| `callback` | `dr1003` |
| `login_method` | `1` |
| `user_account` | 学号（纯数字，如 `1234567890`）；邮箱形式（`xxx@nankai.edu.cn`）会被拒绝 |
| `user_password` | 明文密码 |
| `wlan_user_ip` | 本机 IPv4 |
| `wlan_user_ipv6` | 本机 IPv6（可选） |
| `wlan_user_mac` | 本机 MAC（无冒号小写 hex） |
| `wlan_ac_ip` | （空） |
| `wlan_ac_name` | （空） |
| `jsVersion` | `4.3` |

- **明文参数**（不加密，追加在末尾）: `encrypt=1&v=1234&lang=zh`
  （`v=1234` 来自门户配置，非时间戳）

- **成功响应**:
  ```
  dr1003({"result":0,"msg":"Welcome to Drcom System:3365972160","ret_code":1});
  ```
  （数字为 NAS IP 的十进制形式；`result` 恒为 0，**以 msg 前缀判断成功**）
- **成功响应（会话刷新式重复登录）**:
  ```
  dr1003({"result":0,"msg":"Portal协议认证成功!","ret_code":1});
  ```
  （已在线时再次登录返回；判定规则为 msg 含 `认证成功`）
- **失败响应**:
  - 密码错误: `dr1003({"result":0,"msg":"统一身份认证验证失败","ret_code":1});`
  - 账号不存在/无法解码: `dr1003({"result":0,"msg":"无法获取用户认证账号!","ret_code":1});`

## 4. 登出接口详情（已验证）
- **URL**: `https://netauth.nankai.edu.cn:804/eportal/portal/logout`
- **Method**: GET (JSONP)
- **Query Parameters**（加密规则同登录）:

| 参数 | 值 |
|------|-----|
| `callback` | `dr1004` |
| `login_method` | `1` |
| `user_account` | 学号 |
| `user_password` | **真实密码**（dummy 值不会注销会话） |
| `ac_logout` | `1` |
| `register_mode` | `1` |
| `wlan_user_ip` | 本机 IPv4 |
| `wlan_user_ipv6` | 本机 IPv6（可选） |
| `wlan_vlan_id` | `1` |
| `wlan_user_mac` | 本机 MAC |
| `wlan_ac_ip` | （空） |
| `wlan_ac_name` | （空） |
| `jsVersion` | `4.3` |

- **明文参数**: `encrypt=1&v=1234&lang=zh`
- **成功响应**:
  ```
  dr1004({"result":1,"msg":"Radius注销成功！"});
  ```
  `result: 1` 表示成功。登出成功后 AC 在数秒内停止放行流量（探测转为 302 或连接失败）。

## 5. 密码加密算法
- **密钥**: `'d' ^ 'r' ^ 'c' ^ 'o' ^ 'm'` = `0x77` = `119`（对 `"drcom"` 逐字符异或累加）
- **过程**: 明文每个字符与 119 异或，结果按 2 位小写 hex 拼接（空串保持空）
  ```python
  def enc_pwd(value, key=119):
      return "".join(f"{ord(c) ^ key:02x}" for c in str(value)) if value else ""
  ```
- 示例: `mypassword` → `1a0e0716040400180513`

## 6. 旧版 :801 端点（实测补充）
- **登录可用（明文 upass）**:
  `http://<ac>:801/eportal/?c=ACSetting&a=Login&url=drappall&DDDDD=<学号>&upass=<明文密码URL编码>&R1=0&R2=0&para=00&0MKKey=123456&R6=1`
  - 成功: 响应体含 `msga='Welcome to Drcom System:<nas>'`，无 `Login fail`
  - 失败: `msga='统一身份认证验证失败'` + `Login fail`
  - 注意: :801 期望 **明文** upass；MD5 模式（`md5(pid+pwd+calg)+calg+pid`）与 XOR 模式均被拒绝
    （服务器转发乱码给 CAS）
- **登出不可用**: `c=ACSetting&a=Logout` 只返回模板页（`Test eportal query`），不注销会话。
  必须使用第 4 节的 :804 eportal 接口。

## 7. 已知坑
1. **登录失败过多触发 MAC 封禁**: 连续多次错误登录后，AC 在应用层封禁该 MAC
   （TCP 可连通、HTTP 负载被丢弃，连门户本身也不响应；ping 网关正常）。
   处理: 更换 MAC 地址重新获取 DHCP 租约即可解除
   （`ip link set wlan0 down; ip link set wlan0 address <new>; ip link set wlan0 up`）。
2. **公网实例 ≠ 校园实例**: 从校园内访问 `222.30.38.234:804` 的登录/登出操作的是
   公网实例的会话库，不影响校园 VLAN 内 AC 的会话。校园内应使用 DNS 解析（→内部 AC）。
3. **重复登录**: 已有活动会话时再次登录会失败（`统一身份认证验证失败`），先登出再登录。
4. **浏览器门户页面损坏**: `loadConfig` 服务端 iconv 错误，浏览器登录页不可用，
   使用本脚本直连 API。

## 8. 流程总结
1. **探测**: 本地检测 IP/MAC/IPv6，探测 `baidu` 判断认证状态
2. **登录**: 构造 XOR 加密参数 GET `portal/login`，解析 JSONP，msg 前缀 `Welcome to Drcom System` 或含 `认证成功` 即成功
3. **登出**: 构造 XOR 加密参数（含真实密码）GET `portal/logout`，`result:1` + `Radius注销成功！` 即成功
4. **验证**: 登出后探测 `baidu` 应转为 302 或连接失败
