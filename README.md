# NKU NetLogin

南开大学校园网认证系统（ePortal）自动登录/登出工具。支持身份验证、网络状态检查和会话管理。

## 项目简介

这是一套针对南开大学校园网 ePortal 认证系统的 Python 实现工具。通过逆向工程原生 JavaScript 认证流程，提供了自动化的登录、登出和状态检查功能。

**主要特性：**
- 🔐 自动检测网络信息（IP、MAC 地址等）
- ✅ 支持自动登录和登出
- 📊 查询在线连接状态
- 🔒 安全的密码加密（XOR 算法）
- 🌐 兼容 ePortal 认证门户

## 文件说明

| 文件 | 功能 |
|------|------|
| `login.py` | 登录认证脚本 |
| `logout.py` | 登出脚本 |
| `status.py` | 检查在线状态脚本 |
| `get_config_v2.py` | 获取认证配置 |
| `TECHNICAL_DOCS.md` | 详细的技术文档 |

## 快速开始

### 安装依赖

```bash
pip install requests
```

### 使用示例

#### 登录
```bash
python login.py yourusername yourpassword
```

#### 登出
登出功能目前不可用，疑似南开没有实现登出功能。
```bash
python logout.py
```


## 技术细节

### 认证流程

1. **网络探测** - 访问外部 HTTP 网址触发门户重定向
2. **参数提取** - 从重定向 URL 解析认证所需参数
3. **密码加密** - 使用 XOR 算法加密用户密码
4. **发送请求** - 向认证服务器发送 JSONP 请求
5. **验证响应** - 检查认证结果

### 密码加密算法

使用固定密钥 `119` 的 XOR 加密：

```python
def enc_pwd(password, key=119):
    return "".join([
        hex(ord(c) ^ key)[2:].zfill(2) 
        for c in password
    ])
```

### 核心参数

- `wlanuserip` - 用户 IP 地址
- `wlanacname` - AC 设备名称
- `wlan_user_mac` - 用户 MAC 地址
- `jsVersion` - 认证版本号

详见 [TECHNICAL_DOCS.md](TECHNICAL_DOCS.md)

## 常见问题

### Q: 登录失败提示 "No redirection detected"？
A: 需要连接到南开大学校园网，或检查网络连接状态。

### Q: 如何处理 SSL 证书警告？
A: 脚本中已配置 `verify=False` 以跳过 SSL 验证。生产环境建议添加正确的证书。

### Q: 支持 IPv6？
A: 部分接口支持 IPv6，但主要功能面向 IPv4。

## 安全性提示

⚠️ **注意事项：**
- 不要在公共环境或不信任的计算机上运行此脚本
- 避免硬编码密码，建议通过命令行参数或环境变量传入
- 此工具仅供个人学习和网络维护使用
- 遵守学校网络使用政策

## 环境要求

- Python 3.6+
- requests 库
- 互联网连接（用于网络探测）

## 许可证

MIT License

## 致谢

感谢所有为此项目贡献代码和文档的开发者。

Webportal 技术探测和实现：Google Gemini 3 Flash

---

**相关资源：**
- [南开大学网络信息技术中心](https://www.nankai.edu.cn/)
- [技术文档详解](TECHNICAL_DOCS.md)

如有问题，欢迎提交 Issue 或 Pull Request。
