const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const crypto = require('crypto');
const CryptoJS = require('crypto-js');
const protobuf = require('protobufjs');
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

// 解密JSON字段的中间件
const decryptJsonFields = (req, res, next) => {
    const secretKey = 'json-field-encrypt-2025';
    const { phone, idCard, bankCard } = req.body;

    try {
        // 解密敏感字段
        const decryptedPhone = CryptoJS.AES.decrypt(phone, secretKey).toString(CryptoJS.enc.Utf8);
        const decryptedIdCard = CryptoJS.AES.decrypt(idCard, secretKey).toString(CryptoJS.enc.Utf8);
        const decryptedBankCard = CryptoJS.AES.decrypt(bankCard, secretKey).toString(CryptoJS.enc.Utf8);

        // 验证解密结果
        if (!decryptedPhone || !decryptedIdCard || !decryptedBankCard) {
            return res.status(400).json({ error: '解密敏感字段失败' });
        }

        // 将解密后的数据添加到请求对象
        req.body.decryptedFields = {
            phone: decryptedPhone,
            idCard: decryptedIdCard,
            bankCard: decryptedBankCard
        };

        next();
    } catch (error) {
        res.status(400).json({ error: '解密失败', details: error.message });
    }
};

// 用户信息提交接口
app.post('/api/submit-user-info', decryptJsonFields, (req, res) => {
    const { name, email, city, age, remarks, timestamp, decryptedFields } = req.body;

    // 验证必填字段
    if (!name || !email || !decryptedFields.phone || !decryptedFields.idCard) {
        return res.status(400).json({ error: '缺少必填字段' });
    }

    // 验证手机号格式
    const phoneRegex = /^1[3-9]\d{9}$/;
    if (!phoneRegex.test(decryptedFields.phone)) {
        return res.status(400).json({ error: '手机号格式不正确' });
    }

    // 验证身份证号格式（简单验证）
    const idCardRegex = /^\d{17}[\dX]$/;
    if (!idCardRegex.test(decryptedFields.idCard)) {
        return res.status(400).json({ error: '身份证号格式不正确' });
    }

    // 验证银行卡号格式（简单验证）
    const bankCardRegex = /^\d{16,19}$/;
    if (!bankCardRegex.test(decryptedFields.bankCard)) {
        return res.status(400).json({ error: '银行卡号格式不正确' });
    }

    // 模拟保存到数据库
    const userId = Math.floor(Math.random() * 100000) + 10000;

    // 返回成功响应
    res.json({
        success: true,
        message: '用户信息提交成功',
        userId: userId,
        submitTime: new Date().toISOString(),
        status: '已处理',
        decryptedData: {
            phone: decryptedFields.phone,
            idCard: decryptedFields.idCard.replace(/(\d{6})\d{8}(\d{4})/, '$1********$2'), // 脱敏显示
            bankCard: decryptedFields.bankCard.replace(/(\d{4})\d{8,11}(\d{4})/, '$1****$2') // 脱敏显示
        },
        userInfo: {
            name: name,
            email: email,
            city: city,
            age: age,
            remarks: remarks
        }
    });
});

// 加密响应字段的函数
const encryptResponseField = (value) => {
    const secretKey = 'response-decrypt-2025';
    return CryptoJS.AES.encrypt(value, secretKey).toString();
};

// 用户详细信息接口 - 返回加密字段
app.get('/api/user-details/:userId', (req, res) => {
    const userId = req.params.userId;

    // 模拟用户数据库
    const users = {
        '1001': {
            id: 1001,
            name: '张三',
            email: 'zhangsan@company.com',
            department: '技术部',
            phone: '13800138001',
            idCard: '110101199001011001',
            bankCard: '6222021234567890001',
            address: '北京市朝阳区某某街道123号',
            createdAt: '2023-01-15T08:30:00Z',
            lastLogin: '2025-01-31T10:15:00Z',
            status: '正常'
        },
        '1002': {
            id: 1002,
            name: '李四',
            email: 'lisi@company.com',
            department: '市场部',
            phone: '13800138002',
            idCard: '110101199002022002',
            bankCard: '6222021234567890002',
            address: '上海市浦东新区某某路456号',
            createdAt: '2023-02-20T09:45:00Z',
            lastLogin: '2025-01-31T09:30:00Z',
            status: '正常'
        },
        '1003': {
            id: 1003,
            name: '王五',
            email: 'wangwu@company.com',
            department: '财务部',
            phone: '13800138003',
            idCard: '110101199003033003',
            bankCard: '6222021234567890003',
            address: '广州市天河区某某大道789号',
            createdAt: '2023-03-10T14:20:00Z',
            lastLogin: '2025-01-30T16:45:00Z',
            status: '正常'
        },
        '1004': {
            id: 1004,
            name: '赵六',
            email: 'zhaoliu@company.com',
            department: '人事部',
            phone: '13800138004',
            idCard: '110101199004044004',
            bankCard: '6222021234567890004',
            address: '深圳市南山区某某科技园101号',
            createdAt: '2023-04-05T11:10:00Z',
            lastLogin: '2025-01-29T14:20:00Z',
            status: '正常'
        }
    };

    const user = users[userId];

    if (!user) {
        return res.status(404).json({ error: '用户不存在' });
    }

    // 构建响应，敏感字段加密
    const response = {
        success: true,
        message: '获取用户信息成功',
        data: {
            id: user.id,
            name: user.name,
            email: user.email,
            department: user.department,
            // 敏感字段加密
            encryptedPhone: encryptResponseField(user.phone),
            encryptedIdCard: encryptResponseField(user.idCard),
            encryptedBankCard: encryptResponseField(user.bankCard),
            encryptedAddress: encryptResponseField(user.address),
            // 其他字段保持明文
            createdAt: user.createdAt,
            lastLogin: user.lastLogin,
            status: user.status
        },
        timestamp: new Date().toISOString()
    };

    res.json(response);
});

// 单字段加密消息发送接口
app.post('/api/send-message', (req, res) => {
    const { sender, encryptedMessage, timestamp } = req.body;
    const secretKey = 'single-field-2025';

    // 验证必填字段
    if (!sender || !encryptedMessage) {
        return res.status(400).json({ error: '缺少必填字段' });
    }

    try {
        // 解密消息内容
        const decryptedBytes = CryptoJS.AES.decrypt(encryptedMessage, secretKey);
        const decryptedMessage = decryptedBytes.toString(CryptoJS.enc.Utf8);

        if (!decryptedMessage) {
            return res.status(400).json({ error: '消息解密失败' });
        }

        // 模拟消息处理和存储
        const messageId = Math.random().toString(36).substring(2, 15);

        // 生成服务器回复消息（也加密）
        const replyMessages = [
            '消息已收到，谢谢！',
            '收到您的消息，正在处理中...',
            '感谢您的消息，我们会尽快回复。',
            '您的消息很重要，已记录在案。',
            '消息接收成功，系统已自动处理。'
        ];

        const randomReply = replyMessages[Math.floor(Math.random() * replyMessages.length)];
        const encryptedReply = CryptoJS.AES.encrypt(randomReply, secretKey).toString();

        // 构建响应
        const response = {
            success: true,
            message: '消息发送成功',
            messageId: messageId,
            sender: sender,
            timestamp: new Date().toISOString(),
            // 服务器回复的加密消息
            encryptedContent: encryptedReply,
            // 解密后的原始消息（用于验证）
            originalMessage: decryptedMessage
        };

        res.json(response);

    } catch (error) {
        res.status(400).json({ error: '消息处理失败', details: error.message });
    }
});

// 处理十六进制加密请求体的中间件
const handleHexEncryptedBody = (req, res, next) => {
    const secretKey = 'hex-body-encrypt-2025';

    // 获取原始请求体（十六进制字符串）
    let hexData = '';

    req.on('data', chunk => {
        hexData += chunk.toString();
    });

    req.on('end', () => {
        try {
            // 1. 从十六进制转换回加密的字符串
            const encryptedData = CryptoJS.enc.Hex.parse(hexData).toString(CryptoJS.enc.Utf8);

            // 2. 解密数据
            const decryptedBytes = CryptoJS.AES.decrypt(encryptedData, secretKey);
            const decryptedString = decryptedBytes.toString(CryptoJS.enc.Utf8);

            if (!decryptedString) {
                return res.status(400).json({ error: '请求体解密失败' });
            }

            // 3. 解析JSON
            const jsonData = JSON.parse(decryptedString);

            // 将解密后的数据添加到请求对象
            req.decryptedBody = jsonData;
            req.originalHexData = hexData;
            req.encryptedData = encryptedData;

            next();
        } catch (error) {
            res.status(400).json({ error: '请求体处理失败', details: error.message });
        }
    });
};

// 安全数据提交接口 - 处理十六进制加密的请求体
app.post('/api/secure-submit', handleHexEncryptedBody, (req, res) => {
    const data = req.decryptedBody;

    // 验证必填字段
    if (!data.companyName || !data.contactPerson || !data.email) {
        return res.status(400).json({ error: '缺少必填字段' });
    }

    // 验证邮箱格式
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(data.email)) {
        return res.status(400).json({ error: '邮箱格式不正确' });
    }

    // 验证手机号格式
    const phoneRegex = /^1[3-9]\d{9}$/;
    if (!phoneRegex.test(data.contactPhone)) {
        return res.status(400).json({ error: '手机号格式不正确' });
    }

    // 验证预算范围
    if (data.budget < 0 || data.budget > 10000000) {
        return res.status(400).json({ error: '预算金额超出有效范围' });
    }

    // 模拟数据处理
    const submissionId = Math.random().toString(36).substring(2, 15).toUpperCase();

    // 构建响应
    const response = {
        success: true,
        message: '数据提交成功',
        submissionId: submissionId,
        status: '已接收并处理',
        timestamp: new Date().toISOString(),
        securityLevel: '最高级别加密',
        decryptedData: {
            companyName: data.companyName,
            contactPerson: data.contactPerson,
            budget: data.budget,
            urgency: data.urgency,
            industry: data.industry
        },
        processingInfo: {
            hexDataLength: req.originalHexData.length,
            encryptedDataLength: req.encryptedData.length,
            originalDataSize: JSON.stringify(data).length
        }
    };

    res.json(response);
});

// 加密响应体并转换为十六进制的函数
const encryptResponseToHex = (data) => {
    const secretKey = 'hex-response-decrypt-2025';

    // 1. 将数据转换为JSON字符串
    const jsonString = JSON.stringify(data);

    // 2. 使用AES加密
    const encrypted = CryptoJS.AES.encrypt(jsonString, secretKey).toString();

    // 3. 转换为十六进制
    const hexEncoded = CryptoJS.enc.Utf8.parse(encrypted).toString(CryptoJS.enc.Hex);

    return hexEncoded;
};

// 安全查询接口 - 返回十六进制加密的响应体
app.get('/api/secure-query/:type', (req, res) => {
    const queryType = req.params.type;

    // 模拟不同类型的机密数据
    const mockData = {
        financial: {
            type: 'financial',
            reportType: '年度财务报表',
            period: '2024年度',
            revenue: 15680000,
            profit: 3420000,
            assets: 45600000,
            liabilities: 12300000,
            timestamp: new Date().toISOString(),
            securityLevel: '机密',
            department: '财务部',
            approver: '财务总监'
        },
        employee: {
            type: 'employee',
            name: '李明',
            employeeId: 'EMP001234',
            department: '技术部',
            position: '高级工程师',
            salary: 25000,
            bonus: 50000,
            socialSecurity: '已缴纳',
            timestamp: new Date().toISOString(),
            securityLevel: '机密',
            hireDate: '2020-03-15',
            performance: 'A级'
        },
        customer: {
            type: 'customer',
            companyName: '科技创新集团有限公司',
            customerId: 'CUST789012',
            contactPerson: '王总经理',
            phone: '13800138000',
            email: 'wang@techgroup.com',
            annualRevenue: 8900000,
            creditRating: 'AAA',
            timestamp: new Date().toISOString(),
            securityLevel: '机密',
            contractValue: 12000000,
            paymentStatus: '正常'
        },
        project: {
            type: 'project',
            projectName: '智能数据管理系统',
            projectId: 'PROJ456789',
            manager: '张项目经理',
            budget: 5600000,
            spent: 3200000,
            progress: 68,
            startDate: '2024-01-15',
            expectedEnd: '2025-06-30',
            timestamp: new Date().toISOString(),
            securityLevel: '机密',
            team: '技术团队A组',
            status: '进行中'
        }
    };

    const data = mockData[queryType];

    if (!data) {
        return res.status(404).json({ error: '查询类型不存在' });
    }

    // 加密整个响应并转换为十六进制
    const hexResponse = encryptResponseToHex(data);

    // 设置响应头为纯文本，因为返回的是十六进制字符串
    res.setHeader('Content-Type', 'text/plain');
    res.send(hexResponse);
});

// 处理双向十六进制加密通信的中间件
const handleBidirectionalHexEncryption = (req, res, next) => {
    const secretKey = 'bidirectional-hex-2025';

    // 获取原始请求体（十六进制字符串）
    let hexData = '';

    req.on('data', chunk => {
        hexData += chunk.toString();
    });

    req.on('end', () => {
        try {
            // 1. 从十六进制转换回加密的字符串
            const encryptedData = CryptoJS.enc.Hex.parse(hexData).toString(CryptoJS.enc.Utf8);

            // 2. 解密数据
            const decryptedBytes = CryptoJS.AES.decrypt(encryptedData, secretKey);
            const decryptedString = decryptedBytes.toString(CryptoJS.enc.Utf8);

            if (!decryptedString) {
                return res.status(400).json({ error: '请求体解密失败' });
            }

            // 3. 解析JSON
            const jsonData = JSON.parse(decryptedString);

            // 将解密后的数据添加到请求对象
            req.decryptedBody = jsonData;
            req.originalHexData = hexData;
            req.encryptedData = encryptedData;

            // 添加响应加密函数
            req.encryptResponse = (responseData) => {
                const jsonString = JSON.stringify(responseData);
                const encrypted = CryptoJS.AES.encrypt(jsonString, secretKey).toString();
                const hexEncoded = CryptoJS.enc.Utf8.parse(encrypted).toString(CryptoJS.enc.Hex);
                return hexEncoded;
            };

            next();
        } catch (error) {
            res.status(400).json({ error: '请求体处理失败', details: error.message });
        }
    });
};

// 安全操作接口 - 双向十六进制加密通信
app.post('/api/secure-operation', handleBidirectionalHexEncryption, (req, res) => {
    const data = req.decryptedBody;

    // 验证必填字段
    if (!data.operation || !data.timestamp) {
        return res.status(400).json({ error: '缺少必填字段' });
    }

    // 生成操作ID
    const operationId = Math.random().toString(36).substring(2, 15).toUpperCase();

    // 根据操作类型生成不同的响应
    let responseData = {
        success: true,
        operationId: operationId,
        operation: data.operation,
        status: '执行成功',
        executionTime: new Date().toISOString(),
        securityLevel: 'TOP_SECRET',
        requestId: data.requestId
    };

    // 根据操作类型添加特定的响应数据
    switch(data.operation) {
        case 'transfer':
            responseData.details = {
                amount: data.amount,
                fee: Math.round(data.amount * 0.001), // 0.1% 手续费
                transactionId: 'TXN' + Math.random().toString(36).substring(2, 15).toUpperCase(),
                fromAccount: data.fromAccount.replace(/(\d{4})\d{8}(\d{4})/, '$1****$2'),
                toAccount: data.toAccount.replace(/(\d{4})\d{8}(\d{4})/, '$1****$2'),
                currency: data.currency,
                estimatedArrival: '2-24小时'
            };
            break;

        case 'contract':
            responseData.details = {
                contractNumber: 'CON' + Math.random().toString(36).substring(2, 15).toUpperCase(),
                signatureStatus: '已签署',
                legalStatus: '具有法律效力',
                digitalSignature: 'SHA256:' + Math.random().toString(36).substring(2, 15),
                contractValue: data.value,
                effectiveDate: new Date().toISOString().split('T')[0]
            };
            break;

        case 'audit':
            responseData.details = {
                reportId: 'AUD' + Math.random().toString(36).substring(2, 15).toUpperCase(),
                issuesFound: Math.floor(Math.random() * 5) + 1,
                riskLevel: ['低', '中', '高'][Math.floor(Math.random() * 3)],
                auditScore: Math.floor(Math.random() * 20) + 80,
                recommendations: '建议加强密码策略和访问控制',
                nextAuditDate: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]
            };
            break;

        case 'backup':
            responseData.details = {
                backupId: 'BAK' + Math.random().toString(36).substring(2, 15).toUpperCase(),
                backupSize: (Math.random() * 100 + 50).toFixed(2) + ' GB',
                integrityCheck: '通过',
                compressionRatio: (Math.random() * 0.3 + 0.6).toFixed(2),
                estimatedRestoreTime: Math.floor(Math.random() * 60 + 30) + '分钟',
                storageLocation: data.location === 'cloud' ? '云端存储' : '本地存储'
            };
            break;

        default:
            responseData.details = {
                message: '操作类型未识别，但已安全处理'
            };
    }

    // 加密响应并返回十六进制
    const hexResponse = req.encryptResponse(responseData);

    // 设置响应头为纯文本
    res.setHeader('Content-Type', 'text/plain');
    res.send(hexResponse);
});

// Protocol Buffers schema
let protobufRoot = null;

// 初始化protobuf schema
const initProtobufSchema = async () => {
    try {
        const protoSchema = `
            syntax = "proto3";
            package api;

            message UserInfo {
                string name = 1;
                string email = 2;
                int32 age = 3;
                string phone = 4;
                string address = 5;
                string company = 6;
                string position = 7;
                int64 salary = 8;
                repeated string skills = 9;
                map<string, string> metadata = 10;
            }

            message ProductInfo {
                string name = 1;
                string description = 2;
                double price = 3;
                string category = 4;
                string brand = 5;
                int32 stock = 6;
                repeated string tags = 7;
                map<string, string> attributes = 8;
            }

            message OrderInfo {
                string order_id = 1;
                string customer_name = 2;
                string customer_email = 3;
                repeated ProductInfo products = 4;
                double total_amount = 5;
                string status = 6;
                int64 created_at = 7;
                string shipping_address = 8;
                string payment_method = 9;
            }

            message ApiRequest {
                string request_id = 1;
                int64 timestamp = 2;
                string operation = 3;

                oneof data {
                    UserInfo user_info = 10;
                    ProductInfo product_info = 11;
                    OrderInfo order_info = 12;
                }
            }

            message ApiResponse {
                string request_id = 1;
                int64 timestamp = 2;
                bool success = 3;
                string message = 4;
                int32 code = 5;

                oneof data {
                    UserInfo user_info = 10;
                    ProductInfo product_info = 11;
                    OrderInfo order_info = 12;
                }
            }
        `;

        protobufRoot = protobuf.parse(protoSchema).root;
        console.log('Protocol Buffers schema initialized successfully');
    } catch (error) {
        console.error('Failed to initialize protobuf schema:', error);
    }
};

// 处理protobuf请求体的中间件
const handleProtobufRequest = (req, res, next) => {
    if (!protobufRoot) {
        return res.status(500).json({ error: 'Protocol Buffers schema not initialized' });
    }

    // 获取原始请求体（二进制数据）
    let bufferData = Buffer.alloc(0);

    req.on('data', chunk => {
        bufferData = Buffer.concat([bufferData, chunk]);
    });

    req.on('end', () => {
        try {
            // 解析protobuf请求
            const ApiRequest = protobufRoot.lookupType('api.ApiRequest');
            const message = ApiRequest.decode(bufferData);
            const requestData = ApiRequest.toObject(message);

            // 将解析后的数据添加到请求对象
            req.protobufData = requestData;
            req.originalBuffer = bufferData;

            // 添加响应序列化函数
            req.sendProtobufResponse = (responseData) => {
                try {
                    const ApiResponse = protobufRoot.lookupType('api.ApiResponse');
                    const responseMessage = ApiResponse.create(responseData);
                    const responseBuffer = ApiResponse.encode(responseMessage).finish();

                    res.setHeader('Content-Type', 'application/x-protobuf');
                    res.send(responseBuffer);
                } catch (error) {
                    res.status(500).json({ error: '响应序列化失败', details: error.message });
                }
            };

            next();
        } catch (error) {
            res.status(400).json({ error: 'Protocol Buffers 解析失败', details: error.message });
        }
    });
};

// Protocol Buffers API接口
app.post('/api/protobuf', handleProtobufRequest, (req, res) => {
    const data = req.protobufData;

    // 验证必填字段
    if (!data.request_id || !data.operation) {
        return res.status(400).json({ error: '缺少必填字段' });
    }

    // 构建响应数据
    let responseData = {
        request_id: data.request_id,
        timestamp: Math.floor(Date.now() / 1000),
        success: true,
        message: 'Protocol Buffers 请求处理成功',
        code: 200
    };

    // 根据操作类型处理数据并构建响应
    switch(data.operation) {
        case 'user':
            if (data.user_info) {
                // 模拟用户数据处理
                responseData.user_info = {
                    ...data.user_info,
                    // 添加一些服务器端生成的数据
                    metadata: {
                        ...data.user_info.metadata,
                        'user_id': 'USR' + Math.random().toString(36).substring(2, 15).toUpperCase(),
                        'created_at': new Date().toISOString(),
                        'status': 'active'
                    }
                };
                responseData.message = `用户 ${data.user_info.name} 信息处理成功`;
            }
            break;

        case 'product':
            if (data.product_info) {
                // 模拟产品数据处理
                responseData.product_info = {
                    ...data.product_info,
                    // 添加一些服务器端生成的数据
                    attributes: {
                        ...data.product_info.attributes,
                        'product_id': 'PRD' + Math.random().toString(36).substring(2, 15).toUpperCase(),
                        'created_at': new Date().toISOString(),
                        'status': 'available'
                    }
                };
                responseData.message = `产品 ${data.product_info.name} 信息处理成功`;
            }
            break;

        case 'order':
            if (data.order_info) {
                // 模拟订单数据处理
                responseData.order_info = {
                    ...data.order_info,
                    // 更新订单状态
                    status: 'confirmed',
                    // 添加确认时间
                    created_at: Math.floor(Date.now() / 1000)
                };
                responseData.message = `订单 ${data.order_info.order_id} 处理成功`;
            }
            break;

        default:
            responseData.success = false;
            responseData.message = '不支持的操作类型';
            responseData.code = 400;
    }

    // 发送protobuf响应
    req.sendProtobufResponse(responseData);
});



const port = 48159;

// 启动服务器并初始化protobuf
const startServer = async () => {
    await initProtobufSchema();

    app.listen(port, () => {
        console.log(`Server is running on http://localhost:${port}`);
    });
};

startServer();