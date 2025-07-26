const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const crypto = require('crypto');
const CryptoJS = require('crypto-js');
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

// 解密查询参数的中间件
const decryptQueryParams = (req, res, next) => {
    const encryptedQuery = req.query.q;
    const secretKey = 'query-encrypt-key-2025';

    if (!encryptedQuery) {
        return res.status(400).json({ error: 'Missing encrypted query parameter' });
    }

    try {
        // 解密参数
        const decryptedBytes = CryptoJS.AES.decrypt(encryptedQuery, secretKey);
        const decryptedString = decryptedBytes.toString(CryptoJS.enc.Utf8);
        const params = JSON.parse(decryptedString);

        // 将解密后的参数添加到请求对象
        req.decryptedParams = params;
        next();
    } catch (error) {
        res.status(400).json({ error: 'Invalid encrypted parameters', details: error.message });
    }
};

// 商品搜索接口 - 使用加密的查询参数
app.get('/api/search-products', decryptQueryParams, (req, res) => {
    const { keyword, category, minPrice, maxPrice } = req.decryptedParams;

    // 模拟商品数据
    const allProducts = [
        { id: 1, name: '苹果手机', price: 6999, category: 'electronics' },
        { id: 2, name: '华为手机', price: 4999, category: 'electronics' },
        { id: 3, name: '小米手机', price: 2999, category: 'electronics' },
        { id: 4, name: '时尚T恤', price: 199, category: 'clothing' },
        { id: 5, name: '牛仔裤', price: 299, category: 'clothing' },
        { id: 6, name: 'JavaScript高级程序设计', price: 89, category: 'books' },
        { id: 7, name: 'Vue.js实战', price: 79, category: 'books' },
        { id: 8, name: '智能台灯', price: 299, category: 'home' },
        { id: 9, name: '蓝牙音箱', price: 399, category: 'electronics' },
        { id: 10, name: '运动鞋', price: 599, category: 'clothing' }
    ];

    // 根据条件过滤商品
    let filteredProducts = allProducts.filter(product => {
        const matchesKeyword = !keyword || product.name.includes(keyword);
        const matchesCategory = !category || product.category === category;
        const matchesPrice = product.price >= (minPrice || 0) && product.price <= (maxPrice || 999999);

        return matchesKeyword && matchesCategory && matchesPrice;
    });

    res.json({
        products: filteredProducts,
        searchParams: req.decryptedParams,
        total: filteredProducts.length
    });
});

// 验证登录表单签名的中间件
const validateLoginSign = (req, res, next) => {
    const { username, password, timestamp, sign } = req.body;
    const secretKey = 'form-encrypt-key-2025';

    if (!sign) {
        return res.status(400).json({ error: 'Missing signature' });
    }

    try {
        // 生成期望的签名
        const signString = `${username}${password}${timestamp}`;
        const expectedSign = CryptoJS.HmacSHA256(signString, secretKey).toString();

        if (sign !== expectedSign) {
            return res.status(403).json({ error: 'Invalid signature' });
        }

        // 解密密码
        const decryptedPassword = CryptoJS.AES.decrypt(password, secretKey).toString(CryptoJS.enc.Utf8);
        req.body.decryptedPassword = decryptedPassword;

        next();
    } catch (error) {
        res.status(400).json({ error: 'Invalid encrypted data', details: error.message });
    }
};

// 登录接口
app.post('/api/login', validateLoginSign, (req, res) => {
    const { username, decryptedPassword, rememberMe } = req.body;

    // 模拟用户数据库
    const users = [
        { id: 1, username: 'admin@example.com', password: '123456', name: '管理员' },
        { id: 2, username: 'user@example.com', password: 'password', name: '普通用户' },
        { id: 3, username: 'test', password: 'test123', name: '测试用户' }
    ];

    // 验证用户名和密码
    const user = users.find(u =>
        (u.username === username || u.username.split('@')[0] === username) &&
        u.password === decryptedPassword
    );

    if (!user) {
        return res.status(401).json({ error: '用户名或密码错误' });
    }

    // 生成模拟token
    const token = CryptoJS.HmacSHA256(`${user.id}${Date.now()}`, 'token-secret').toString();

    res.json({
        success: true,
        message: '登录成功',
        user: {
            id: user.id,
            username: user.name,
            email: user.username
        },
        token: token,
        loginTime: new Date().toISOString(),
        rememberMe: rememberMe
    });
});



const port = 48159;
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});