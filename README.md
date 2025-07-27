# 🎯 XHR Hook Goat

<div align="center">

![XHR Hook Goat](https://img.shields.io/badge/XHR%20Hook%20Goat-v1.0.0-blue?style=for-the-badge&logo=javascript)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Cases](https://img.shields.io/badge/Cases-16-orange?style=for-the-badge)
![Completion](https://img.shields.io/badge/Completion-100%25-brightgreen?style=for-the-badge)

**专业的XHR逆向工程练习靶场**

涵盖从基础到高级的完整XHR逆向技术栈，包括加密解密、签名验证、协议缓冲区、拦截器自动化、流媒体DRM等16个实战案例

[🚀 在线体验](https://jsrei.github.io/js-xhr-hook-goat/) | [📖 文档](#文档) | [🎯 案例列表](#案例列表) | [🛠️ 本地部署](#本地部署)

</div>

---

## 📋 目录

- [项目简介](#项目简介)
- [技术特色](#技术特色)
- [案例列表](#案例列表)
- [技术栈](#技术栈)
- [快速开始](#快速开始)
- [本地部署](#本地部署)
- [项目结构](#项目结构)
- [核心算法](#核心算法)
- [学习路径](#学习路径)
- [贡献指南](#贡献指南)
- [许可证](#许可证)

## 🎯 项目简介

XHR Hook Goat 是一个专业的XHR逆向工程练习靶场，旨在为安全研究人员、渗透测试工程师、前端开发者提供完整的XHR逆向技术学习和实践平台。

### 🌟 项目亮点

- **🎯 完整覆盖**: 16个实战案例，涵盖XHR逆向的完整技术栈
- **📈 难度梯度**: 从基础到专家级，循序渐进的学习路径
- **🔧 真实场景**: 模拟金融、企业、流媒体等真实应用场景
- **🚀 现代技术**: 包含Protocol Buffers、拦截器、DRM等前沿技术
- **📱 响应式设计**: 支持桌面端和移动端完美体验
- **🌐 双重部署**: 支持本地开发和GitHub Pages在线访问

### 🎓 适用人群

- **安全研究人员**: 学习和研究XHR逆向技术
- **渗透测试工程师**: 提升Web应用安全测试技能
- **前端开发者**: 了解前端安全和加密技术
- **网络安全学生**: 系统学习Web安全相关知识
- **逆向工程师**: 掌握JavaScript逆向分析技术

## ✨ 技术特色

### 🔐 加密技术覆盖
- **对称加密**: AES-128/256-CBC/GCM
- **签名验证**: HMAC-SHA256, MD5
- **编码方式**: Base64, 十六进制
- **密钥管理**: 动态密钥生成和验证

### 🌐 通信协议支持
- **传统HTTP**: Query String, Form Data, JSON
- **现代协议**: Protocol Buffers 双向通信
- **流媒体**: HLS/DASH 视频片段加密
- **实时通信**: WebSocket 加密通信

### 🛡️ 安全机制实现
- **防重放攻击**: 时间戳验证机制
- **请求完整性**: 多层签名验证
- **会话管理**: 加密Cookie和Token
- **自动化拦截**: XMLHttpRequest拦截器

## 📚 案例列表

### 🔰 基础加密案例 (4个)
| 编号 | 案例名称 | 技术栈 | 难度 |
|------|----------|--------|------|
| 1 | [请求参数签名验证](public/query-string-param-sign.html) | HMAC-SHA256 | 🟢 基础 |
| 2 | [查询参数加密](public/query-string-param-encrypt.html) | AES + Base64 | 🟢 基础 |
| 3 | [表单参数加密](public/form-body-encrypt.html) | AES + 签名 | 🟢 基础 |
| 6 | [单字段加密](public/single-field-encrypt.html) | AES-GCM | 🟢 基础 |

### 🔶 中级加密案例 (4个)
| 编号 | 案例名称 | 技术栈 | 难度 |
|------|----------|--------|------|
| 4 | [JSON字段加密](public/json-body-field-encrypt.html) | 多字段AES | 🟡 中级 |
| 5 | [响应字段解密](public/response-field-decrypt.html) | 响应解密 | 🟡 中级 |
| 13 | [请求头签名验证](public/header-sign.html) | Header签名 | 🟡 中级 |
| 14 | [响应头加密Cookie](public/response-header-cookie.html) | Cookie加密 | 🟡 中级 |

### 🔴 高级加密案例 (3个)
| 编号 | 案例名称 | 技术栈 | 难度 |
|------|----------|--------|------|
| 7 | [十六进制请求体加密](public/hex-body-encrypt.html) | Hex + AES | 🔴 高级 |
| 8 | [十六进制响应体解密](public/hex-response-decrypt.html) | Hex解密 | 🔴 高级 |
| 9 | [双向十六进制加密](public/bidirectional-hex-encrypt.html) | 双向Hex | 🔴 高级 |

### 🚀 专家级案例 (5个)
| 编号 | 案例名称 | 技术栈 | 难度 |
|------|----------|--------|------|
| 10 | [Protocol Buffers 请求体](public/protobuf-request.html) | Protobuf | 🔥 专家 |
| 11 | [Protocol Buffers 响应体](public/protobuf-response.html) | Protobuf | 🔥 专家 |
| 12 | [双向 Protocol Buffers](public/bidirectional-protobuf.html) | 双向Protobuf | 🔥 专家 |
| 15 | [拦截器自动签名](public/interceptor-encryption.html) | 拦截器 | 🔥 专家 |
| 16 | [加密视频片段](public/video-segment-encryption.html) | 流媒体DRM | 🔥 专家 |

## 🛠️ 技术栈

### 前端技术
```
JavaScript (ES6+)    - 核心逻辑实现
CryptoJS 4.1.1      - 加密算法库
jQuery 3.6.0        - DOM操作和AJAX
Protobuf 7.2.5       - 二进制序列化
HTML5 + CSS3        - 现代化UI设计
```

### 后端技术
```
Node.js             - 服务器运行环境
Express.js          - Web框架
Crypto (内置)        - 服务端加密
CORS               - 跨域支持
```

### 加密算法
```
AES-128/256-CBC     - 对称加密
AES-GCM            - 认证加密
HMAC-SHA256        - 消息认证码
MD5                - 快速哈希
Base64             - 编码转换
Hex                - 十六进制编码
```

### 协议支持
```
HTTP/HTTPS         - 基础通信协议
Protocol Buffers   - 高效二进制序列化
HLS/DASH          - 流媒体协议
XMLHttpRequest    - AJAX通信
```

## 🚀 快速开始

### 在线体验
直接访问 [https://jsrei.github.io/js-xhr-hook-goat/](https://jsrei.github.io/js-xhr-hook-goat/) 即可开始学习。

### 本地运行
```bash
# 1. 克隆项目
git clone https://github.com/JSREI/js-xhr-hook-goat.git
cd js-xhr-hook-goat

# 2. 安装依赖
npm install

# 3. 启动服务器
npm start
# 或者使用便捷脚本
./start.sh

# 4. 访问应用
open http://localhost:48159
```

## 🏗️ 本地部署

### 开发环境
```bash
# 启动开发服务器（支持热重载）
npm run dev

# 启动生产服务器
npm start

# 后台运行
npm run start:daemon

# 停止服务器
npm run stop
```

### 构建部署
```bash
# 构建静态文件用于GitHub Pages
npm run pages

# 构建并预览
npm run build && npm run preview

# 清理构建文件
npm run clean
```

### Docker部署
```bash
# 构建Docker镜像
docker build -t xhr-hook-goat .

# 运行容器
docker run -p 48159:48159 xhr-hook-goat

# 使用docker-compose
docker-compose up -d
```

## 📁 项目结构

```
js-xhr-hook-goat/
├── 📁 public/                    # 前端静态文件
│   ├── 📄 index.html            # 主页面
│   ├── 📄 *.html               # 各个案例页面
│   ├── 📁 libs/                # 第三方库
│   │   ├── crypto-js-4.1.1.min.js
│   │   ├── jquery-3.6.0.min.js
│   │   └── protobuf-7.2.5.min.js
│   └── 📁 proto/               # Protocol Buffers定义
│       └── api.proto
├── 📁 fake-api-server/          # 静态API响应
│   └── 📁 api/                 # 模拟API端点
├── 📁 dist/                     # 构建输出目录
├── 📄 server.js                 # Node.js服务器
├── 📄 pages.js                  # 构建脚本
├── 📄 start.sh                  # 启动脚本
├── 📄 package.json              # 项目配置
└── 📄 README.md                 # 项目文档
```

### 核心文件说明

| 文件/目录 | 说明 |
|-----------|------|
| `public/` | 前端页面和资源文件 |
| `server.js` | Express服务器，提供API和静态文件服务 |
| `fake-api-server/` | GitHub Pages使用的静态JSON响应 |
| `pages.js` | 构建脚本，复制文件到dist目录 |
| `start.sh` | 便捷启动脚本，支持进程管理 |

## 🔐 核心算法

### 1. HMAC-SHA256 签名验证
```javascript
// 客户端签名生成
const timestamp = Math.floor(Date.now() / 1000);
const message = `/api/items?timestamp=${timestamp}`;
const signature = CryptoJS.HmacSHA256(message, 'secret-key').toString();

// 服务端验证
const expectedSignature = crypto
  .createHmac('sha256', 'secret-key')
  .update(message)
  .digest('hex');
```

### 2. AES加密解密
```javascript
// AES-256-CBC 加密
const key = CryptoJS.enc.Utf8.parse('32-char-secret-key-for-aes-256');
const iv = CryptoJS.lib.WordArray.random(16);
const encrypted = CryptoJS.AES.encrypt(data, key, {
  iv: iv,
  mode: CryptoJS.mode.CBC,
  padding: CryptoJS.pad.Pkcs7
});

// AES-GCM 认证加密
const encrypted = CryptoJS.AES.encrypt(data, key, {
  mode: CryptoJS.mode.GCM,
  iv: iv
});
```

### 3. Protocol Buffers 序列化
```javascript
// 定义消息结构
const UserRequest = protobuf.Type.fromJSON("UserRequest", {
  fields: {
    userId: { type: "int32", id: 1 },
    action: { type: "string", id: 2 },
    timestamp: { type: "int64", id: 3 }
  }
});

// 序列化和反序列化
const message = UserRequest.create({ userId: 123, action: "query" });
const buffer = UserRequest.encode(message).finish();
const decoded = UserRequest.decode(buffer);
```

### 4. 拦截器自动签名
```javascript
// XMLHttpRequest 拦截器
const originalXHR = window.XMLHttpRequest;
window.XMLHttpRequest = function() {
  const xhr = new originalXHR();
  const originalSend = xhr.send;

  xhr.send = function(data) {
    // 自动添加签名
    const signedData = addSignature(data);
    return originalSend.call(this, signedData);
  };

  return xhr;
};
```

### 5. 视频片段加密
```javascript
// HLS/DASH 视频片段加密
function encryptVideoSegment(segmentData, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipher('aes-128-cbc', key);

  let encrypted = cipher.update(segmentData, 'utf8', 'base64');
  encrypted += cipher.final('base64');

  return { encrypted, iv: iv.toString('hex') };
}
```

## 🎓 学习路径

### 🔰 初学者路径 (1-2周)
```
第1步: 请求参数签名验证 → 理解基础签名概念
第2步: 查询参数加密 → 学习AES加密基础
第3步: 表单参数加密 → 掌握POST请求加密
第4步: 单字段加密 → 了解字段级加密
```

### 🔶 进阶者路径 (2-3周)
```
第5步: JSON字段加密 → 复杂数据结构加密
第6步: 响应字段解密 → 双向加密通信
第7步: 请求头签名验证 → HTTP头部安全
第8步: 响应头加密Cookie → 会话管理安全
```

### 🔴 高级者路径 (3-4周)
```
第9步: 十六进制请求体加密 → 高级编码技术
第10步: 十六进制响应体解密 → 复杂解密流程
第11步: 双向十六进制加密 → 完整加密通信
```

### 🚀 专家级路径 (4-6周)
```
第12步: Protocol Buffers 请求体 → 现代序列化协议
第13步: Protocol Buffers 响应体 → 高效二进制通信
第14步: 双向 Protocol Buffers → 完整Protobuf方案
第15步: 拦截器自动签名 → 企业级自动化方案
第16步: 加密视频片段 → 流媒体DRM技术
```

### 📚 学习建议

1. **循序渐进**: 按照难度等级逐步学习，不要跳跃
2. **动手实践**: 每个案例都要亲自操作和调试
3. **理解原理**: 不仅要会用，更要理解背后的加密原理
4. **对比分析**: 比较不同加密方案的优缺点和适用场景
5. **扩展思考**: 思考如何在实际项目中应用这些技术

### 🎯 学习目标

- **基础级**: 掌握常见的Web加密技术和签名验证
- **中级**: 理解复杂的加密通信流程和安全机制
- **高级**: 能够分析和破解复杂的加密方案
- **专家级**: 具备设计企业级安全方案的能力

## 🤝 贡献指南

我们欢迎所有形式的贡献！无论是新功能、bug修复、文档改进还是案例优化。

### 🔧 开发贡献

1. **Fork 项目**
   ```bash
   git clone https://github.com/your-username/js-xhr-hook-goat.git
   cd js-xhr-hook-goat
   ```

2. **创建功能分支**
   ```bash
   git checkout -b feature/new-case
   ```

3. **开发和测试**
   ```bash
   npm install
   npm start
   # 在 http://localhost:48159 测试你的更改
   ```

4. **提交更改**
   ```bash
   git add .
   git commit -m "feat: 添加新的加密案例"
   git push origin feature/new-case
   ```

5. **创建 Pull Request**

### 📝 文档贡献

- 改进现有文档的清晰度和准确性
- 添加更多的代码示例和解释
- 翻译文档到其他语言
- 添加视频教程和图解说明

### 🐛 问题报告

如果你发现了bug或有改进建议，请：

1. 检查是否已有相关的 [Issue](https://github.com/JSREI/js-xhr-hook-goat/issues)
2. 创建新的 Issue，详细描述问题
3. 提供复现步骤和环境信息
4. 如果可能，提供修复建议

### 💡 新案例贡献

我们特别欢迎新的XHR逆向案例：

- **新的加密算法**: RSA、ECC、国密算法等
- **新的应用场景**: IoT设备、区块链、AI接口等
- **新的攻击技术**: 时序攻击、侧信道攻击等
- **新的防护机制**: 代码混淆、反调试等

### 📋 贡献规范

- 遵循现有的代码风格和结构
- 添加适当的注释和文档
- 确保新功能有对应的测试
- 更新相关的README和文档

## 🌟 致谢

感谢所有为这个项目做出贡献的开发者和安全研究人员！

### 🏆 主要贡献者

- [@CC11001100](https://github.com/CC11001100) - 项目创始人和主要维护者

### 🎯 特别感谢

- **CryptoJS** - 提供强大的JavaScript加密库
- **Protocol Buffers** - 高效的序列化协议
- **Express.js** - 简洁的Web框架
- **GitHub Pages** - 免费的静态网站托管

### 🔗 相关项目

- [DVWA](https://github.com/digininja/DVWA) - Web应用安全测试
- [WebGoat](https://github.com/WebGoat/WebGoat) - Web安全学习平台
- [Damn Vulnerable Node Application](https://github.com/appsecco/dvna) - Node.js安全测试

## 📄 许可证

本项目采用 [MIT License](LICENSE) 开源协议。

```
MIT License

Copyright (c) 2025 JSREI

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 📞 联系我们

- **GitHub Issues**: [提交问题和建议](https://github.com/JSREI/js-xhr-hook-goat/issues)
- **GitHub Discussions**: [参与讨论](https://github.com/JSREI/js-xhr-hook-goat/discussions)
- **项目主页**: [https://jsrei.github.io/js-xhr-hook-goat/](https://jsrei.github.io/js-xhr-hook-goat/)

---

<div align="center">

**🎯 XHR Hook Goat - 让XHR逆向学习更简单！**

如果这个项目对你有帮助，请给我们一个 ⭐ Star！

[⬆️ 回到顶部](#-xhr-hook-goat)

</div>
