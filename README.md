# NKU NetLogin

南开大学校园网认证系统（ePortal）自动登录/登出工具。协议已在校内实测验证（2026-08，LicheePi 4A）。

## 项目简介

针对南开大学校园网 Dr.COM/ePortal 认证系统的 Python 实现工具。通过逆向门户 JavaScript 并在校园网 VLAN 内实测，提供自动化的登录、登出和网络状态检测。

**主要特性：**
- 🐧 纯标准库实现，无第三方依赖（不需要 `pip install`）
- 📶 本地自动检测 IP / MAC / IPv6，无需解析重定向 URL
- ✅ 登录：ePortal `portal/login` API（XOR-119 加密），成功/失败均有明确判定
- 🚪 登出：ePortal `portal/logout` API（需真实密码），成功后验证流量放行状态
- 🔍 认证状态探测（在线 / 拦截中 / 硬封禁）

## 文件说明

| 文件 | 功能 |
|------|------|
| `login.py` | 登录脚本（同时提供共享的检测/加密函数） |
| `logout.py` | 登出脚本 |
| `TECHNICAL_DOCS.md` | 详细技术文档（含实测协议、响应格式、已知坑） |

## 快速开始

无需安装依赖（Python 3.7+，macOS/Linux 均可运行，MAC 检测以 Linux 为主）。

#### 登录
```bash
python3 login.py <学号> <密码>
```
成功时输出 `Login succeeded.`（响应 msg 为 `Welcome to Drcom System:<NAS IP>`；会话刷新式重复登录为 `Portal协议认证成功!`）。

#### 登出
```bash
python3 logout.py <学号> <密码>
```
成功时输出 `Logout succeeded.`（响应 `{"result":1,"msg":"Radius注销成功！"}`），并验证流量已停止放行。

#### 示例
```bash
python3 login.py <学号> <密码>
python3 logout.py <学号> <密码>
```

## 技术细节

### 认证流程
1. **本地检测** - UDP connect 取校园网出口 IP，`/sys/class/net` 取 MAC
2. **状态探测** - 请求 `http://www.baidu.com`（不跟随重定向）：200=在线，302=未认证，连接失败=封禁
3. **参数加密** - 所有参数值用 XOR（密钥 119）逐字符异或后转 2 位小写 hex
4. **发送请求** - GET 门户 API（JSONP 响应）
5. **验证响应** - 解析 JSONP 中的 JSON，按 `msg` / `result` 判定结果

### 密码加密算法
固定密钥 `119`（`'d'^'r'^'c'^'o'^'m'`）的 XOR 加密：

```python
def enc_pwd(value, key=119):
    return "".join(f"{ord(c) ^ key:02x}" for c in str(value)) if value else ""
```

### 核心接口
- 登录: `https://netauth.nankai.edu.cn:804/eportal/portal/login`
- 登出: `https://netauth.nankai.edu.cn:804/eportal/portal/logout`
- 明文后缀: `encrypt=1&v=1234&lang=zh`

详见 [TECHNICAL_DOCS.md](TECHNICAL_DOCS.md)（含旧版 :801 端点、MAC 封禁处理等实测细节）。

## 常见问题

### Q: 登录失败 "统一身份认证验证失败"？
A: 密码错误，或已有活动会话（重复登录）。先 `logout.py` 再登录。账号必须是纯学号，
不要带邮箱后缀（`@nankai.edu.cn` 形式会被拒绝）。

### Q: 所有请求都无响应（含门户本身）？
A: 连续多次登录失败会触发 AC 对 MAC 的应用层封禁。Linux 下更换 MAC 地址重新获取 DHCP 即可解除，
详见 TECHNICAL_DOCS.md 第 7 节。

### Q: 如何处理 SSL 证书警告？
A: 脚本已用 `ssl.CERT_NONE` 跳过证书验证（校内门户证书不受公共 CA 信任）。

### Q: 在 macOS 上运行？
A: 可以（IP 探测为跨平台实现；MAC 检测在无 `/sys` 时回退到 `uuid.getnode()`，
可能与网卡实际 MAC 不一致，登出可能不生效）。

## 安全性提示

⚠️ **注意事项：**
- 不要在公共环境或不信任的计算机上运行此脚本
- 避免硬编码密码，建议通过命令行参数或环境变量传入
- 此工具仅供个人学习和网络维护使用
- 遵守学校网络使用政策

## 许可证

MIT License
