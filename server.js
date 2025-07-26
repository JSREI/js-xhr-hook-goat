const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const crypto = require('crypto');
const {join} = require("node:path");

// 设置静态文件目录
app.use(express.static(join(__dirname, 'public')));
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());

// 定义一个简单的签名验证中间件
const validateSign = (req, res, next) => {
    const sign = req.query.sign;
    const secretKey = 'my-secret-key'; // 替换为你的密钥

    // 生成签名的原始字符串 (使用URL路径)
    const originalString = req.path;

    // 使用 HMAC-SHA256 算法生成签名
    const expectedSign = crypto
        .createHmac('sha256', secretKey)
        .update(originalString)
        .digest('hex');

    // 验证签名是否匹配
    if (sign === expectedSign) {
        next();
    } else {
        res.status(403).json({ error: 'Invalid sign', expected: expectedSign, received: sign });
    }
};

// 列表接口
app.get('/api/items', validateSign, (req, res) => {
    // 这里可以替换为从数据库加载数据
    const items = [
        { id: 1, name: 'Item 1' },
        { id: 2, name: 'Item 2' },
        { id: 3, name: 'Item 3' },
    ];
    res.json({ items });
});



const port = 48159;
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});