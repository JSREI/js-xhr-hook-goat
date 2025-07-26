# JS XHR Hook Goat

一个用于测试 XHR Hook 的靶场项目，演示请求参数签名验证。

## 功能特性

- 演示 AJAX 请求参数签名
- 支持本地开发和 GitHub Pages 部署
- 使用 HMAC-SHA256 算法进行签名验证

## 本地运行

1. 安装依赖：
```bash
npm install
```

2. 启动开发服务器：
```bash
npm start
```

3. 访问 http://localhost:48159

## GitHub Pages 部署

1. 构建静态文件：
```bash
npm run pages
```

2. 部署到 GitHub Pages：
   - 推送代码到 main 分支
   - GitHub Actions 会自动构建并部署到 gh-pages 分支

## 项目结构

- `public/` - 前端静态文件
- `fake-api-server/` - GitHub Pages 使用的静态 API 响应
- `server.js` - 本地开发服务器
- `pages.js` - 构建脚本，将文件复制到 dist 目录

## 签名算法

使用 HMAC-SHA256 算法对请求路径进行签名：

```javascript
const sign = CryptoJS.HmacSHA256('/api/items', 'my-secret-key').toString();
```

## 环境检测

前端会自动检测运行环境：
- 本地开发：使用动态 API 接口（需要签名验证）
- GitHub Pages：使用静态 JSON 文件
