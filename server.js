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



const port = 48159;
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});