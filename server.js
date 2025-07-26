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

// Protocol Buffers 响应接口
app.get('/api/protobuf-response', (req, res) => {
    if (!protobufRoot) {
        return res.status(500).json({ error: 'Protocol Buffers schema not initialized' });
    }

    const category = req.query.category;
    const option = req.query.option;

    if (!category || !option) {
        return res.status(400).json({ error: '缺少必填参数: category, option' });
    }

    try {
        // 定义响应schema
        const responseSchema = `
            syntax = "proto3";
            package api;

            message DataPoint {
                string label = 1;
                double value = 2;
                string unit = 3;
                int64 timestamp = 4;
            }

            message ChartData {
                string chart_type = 1;
                string title = 2;
                repeated DataPoint data_points = 3;
                map<string, string> metadata = 4;
            }

            message ReportData {
                string report_id = 1;
                string title = 2;
                string description = 3;
                repeated ChartData charts = 4;
                map<string, double> summary_metrics = 5;
                int64 generated_at = 6;
            }

            message DataResponse {
                string request_id = 1;
                int64 timestamp = 2;
                bool success = 3;
                string message = 4;
                int32 code = 5;
                string category = 6;
                string option = 7;
                ReportData report_data = 8;
            }
        `;

        const responseRoot = protobuf.parse(responseSchema).root;
        const DataResponse = responseRoot.lookupType('api.DataResponse');

        // 生成模拟数据
        const mockData = generateMockData(category, option);

        // 创建protobuf响应
        const responseMessage = DataResponse.create(mockData);
        const responseBuffer = DataResponse.encode(responseMessage).finish();

        // 设置响应头并发送二进制数据
        res.setHeader('Content-Type', 'application/x-protobuf');
        res.send(responseBuffer);

    } catch (error) {
        res.status(500).json({ error: 'Protocol Buffers 响应生成失败', details: error.message });
    }
});

// 生成模拟数据的函数
function generateMockData(category, option) {
    const requestId = Math.random().toString(36).substring(2, 15);
    const timestamp = Math.floor(Date.now() / 1000);

    const baseResponse = {
        request_id: requestId,
        timestamp: timestamp,
        success: true,
        message: `${category}-${option} 数据获取成功`,
        code: 200,
        category: category,
        option: option
    };

    // 根据类型生成不同的报告数据
    const reportData = {
        report_id: 'RPT' + Math.random().toString(36).substring(2, 15).toUpperCase(),
        generated_at: timestamp
    };

    switch(category) {
        case 'analytics':
            reportData.title = getAnalyticsTitle(option);
            reportData.description = getAnalyticsDescription(option);
            reportData.charts = generateAnalyticsCharts(option);
            reportData.summary_metrics = generateAnalyticsMetrics(option);
            break;

        case 'reports':
            reportData.title = getReportsTitle(option);
            reportData.description = getReportsDescription(option);
            reportData.charts = generateReportsCharts(option);
            reportData.summary_metrics = generateReportsMetrics(option);
            break;

        case 'statistics':
            reportData.title = getStatisticsTitle(option);
            reportData.description = getStatisticsDescription(option);
            reportData.charts = generateStatisticsCharts(option);
            reportData.summary_metrics = generateStatisticsMetrics(option);
            break;

        case 'insights':
            reportData.title = getInsightsTitle(option);
            reportData.description = getInsightsDescription(option);
            reportData.charts = generateInsightsCharts(option);
            reportData.summary_metrics = generateInsightsMetrics(option);
            break;

        default:
            reportData.title = '未知数据类型';
            reportData.description = '无法识别的数据类型';
            reportData.charts = [];
            reportData.summary_metrics = {};
    }

    return {
        ...baseResponse,
        report_data: reportData
    };
}

// 辅助函数：生成标题
function getAnalyticsTitle(option) {
    const titles = {
        sales: '销售数据分析报告',
        revenue: '收入分析报告',
        customers: '客户分析报告',
        products: '产品分析报告'
    };
    return titles[option] || '业务分析报告';
}

function getReportsTitle(option) {
    const titles = {
        performance: '系统性能报告',
        errors: '错误日志报告',
        security: '安全审计报告',
        usage: '系统使用情况报告'
    };
    return titles[option] || '系统报告';
}

function getStatisticsTitle(option) {
    const titles = {
        traffic: '流量统计报告',
        conversion: '转化率统计报告',
        engagement: '用户参与度统计',
        retention: '用户留存分析报告'
    };
    return titles[option] || '统计数据报告';
}

function getInsightsTitle(option) {
    const titles = {
        trends: '趋势预测分析',
        recommendations: '智能推荐报告',
        anomalies: '异常检测报告',
        forecasting: '预测分析报告'
    };
    return titles[option] || '深度洞察报告';
}

// 辅助函数：生成描述
function getAnalyticsDescription(option) {
    const descriptions = {
        sales: '基于最近30天的销售数据，分析销售趋势、热门产品和销售渠道表现',
        revenue: '分析各业务线收入贡献，识别增长机会和风险点',
        customers: '深入分析客户行为模式、价值分布和生命周期',
        products: '评估产品性能、市场接受度和优化建议'
    };
    return descriptions[option] || '业务数据深度分析';
}

function getReportsDescription(option) {
    const descriptions = {
        performance: '系统各组件性能指标监控，包括响应时间、吞吐量和资源使用率',
        errors: '系统错误日志汇总分析，识别常见问题和解决方案',
        security: '安全事件监控和威胁分析，确保系统安全性',
        usage: '用户使用行为分析，优化用户体验和系统设计'
    };
    return descriptions[option] || '系统运行状况分析';
}

function getStatisticsDescription(option) {
    const descriptions = {
        traffic: '网站流量来源分析，包括访问量、页面浏览量和用户行为路径',
        conversion: '转化漏斗分析，识别转化瓶颈和优化机会',
        engagement: '用户参与度指标分析，包括停留时间、互动频率等',
        retention: '用户留存率分析，了解用户粘性和流失原因'
    };
    return descriptions[option] || '数据统计分析';
}

function getInsightsDescription(option) {
    const descriptions = {
        trends: '基于历史数据和机器学习算法预测未来趋势',
        recommendations: 'AI驱动的个性化推荐和业务优化建议',
        anomalies: '智能异常检测，及时发现数据异常和潜在问题',
        forecasting: '预测模型分析，为决策提供数据支持'
    };
    return descriptions[option] || 'AI驱动的深度洞察';
}

// 生成图表数据的函数
function generateAnalyticsCharts(option) {
    const charts = [];
    const now = Date.now();

    switch(option) {
        case 'sales':
            charts.push({
                chart_type: 'line',
                title: '销售趋势图',
                data_points: Array.from({length: 7}, (_, i) => ({
                    label: `第${i+1}天`,
                    value: Math.random() * 10000 + 5000,
                    unit: '元',
                    timestamp: Math.floor((now - (6-i) * 24 * 60 * 60 * 1000) / 1000)
                })),
                metadata: { period: '最近7天', currency: 'CNY' }
            });
            break;
        case 'revenue':
            charts.push({
                chart_type: 'bar',
                title: '收入分布图',
                data_points: [
                    { label: '产品A', value: 45000, unit: '元', timestamp: Math.floor(now / 1000) },
                    { label: '产品B', value: 32000, unit: '元', timestamp: Math.floor(now / 1000) },
                    { label: '产品C', value: 28000, unit: '元', timestamp: Math.floor(now / 1000) }
                ],
                metadata: { period: '本月', currency: 'CNY' }
            });
            break;
        case 'customers':
            charts.push({
                chart_type: 'pie',
                title: '客户分布图',
                data_points: [
                    { label: '新客户', value: 35, unit: '%', timestamp: Math.floor(now / 1000) },
                    { label: '老客户', value: 45, unit: '%', timestamp: Math.floor(now / 1000) },
                    { label: '流失客户', value: 20, unit: '%', timestamp: Math.floor(now / 1000) }
                ],
                metadata: { total_customers: '1250' }
            });
            break;
        case 'products':
            charts.push({
                chart_type: 'bar',
                title: '产品销量排行',
                data_points: [
                    { label: '智能手机', value: 1250, unit: '台', timestamp: Math.floor(now / 1000) },
                    { label: '平板电脑', value: 890, unit: '台', timestamp: Math.floor(now / 1000) },
                    { label: '智能手表', value: 650, unit: '台', timestamp: Math.floor(now / 1000) }
                ],
                metadata: { period: '本月' }
            });
            break;
    }

    return charts;
}

function generateReportsCharts(option) {
    const charts = [];
    const now = Date.now();

    switch(option) {
        case 'performance':
            charts.push({
                chart_type: 'line',
                title: '系统响应时间',
                data_points: Array.from({length: 24}, (_, i) => ({
                    label: `${i}:00`,
                    value: Math.random() * 200 + 100,
                    unit: 'ms',
                    timestamp: Math.floor((now - (23-i) * 60 * 60 * 1000) / 1000)
                })),
                metadata: { period: '最近24小时' }
            });
            break;
        case 'errors':
            charts.push({
                chart_type: 'bar',
                title: '错误类型分布',
                data_points: [
                    { label: '404错误', value: 125, unit: '次', timestamp: Math.floor(now / 1000) },
                    { label: '500错误', value: 45, unit: '次', timestamp: Math.floor(now / 1000) },
                    { label: '超时错误', value: 32, unit: '次', timestamp: Math.floor(now / 1000) }
                ],
                metadata: { period: '今日' }
            });
            break;
        case 'security':
            charts.push({
                chart_type: 'line',
                title: '安全事件趋势',
                data_points: Array.from({length: 7}, (_, i) => ({
                    label: `第${i+1}天`,
                    value: Math.floor(Math.random() * 20),
                    unit: '次',
                    timestamp: Math.floor((now - (6-i) * 24 * 60 * 60 * 1000) / 1000)
                })),
                metadata: { period: '最近7天' }
            });
            break;
        case 'usage':
            charts.push({
                chart_type: 'area',
                title: '用户活跃度',
                data_points: Array.from({length: 12}, (_, i) => ({
                    label: `${i+1}月`,
                    value: Math.random() * 5000 + 2000,
                    unit: '人',
                    timestamp: Math.floor((now - (11-i) * 30 * 24 * 60 * 60 * 1000) / 1000)
                })),
                metadata: { period: '最近12个月' }
            });
            break;
    }

    return charts;
}

function generateStatisticsCharts(option) {
    const charts = [];
    const now = Date.now();

    switch(option) {
        case 'traffic':
            charts.push({
                chart_type: 'line',
                title: '网站流量趋势',
                data_points: Array.from({length: 30}, (_, i) => ({
                    label: `第${i+1}天`,
                    value: Math.random() * 10000 + 5000,
                    unit: 'PV',
                    timestamp: Math.floor((now - (29-i) * 24 * 60 * 60 * 1000) / 1000)
                })),
                metadata: { period: '最近30天' }
            });
            break;
        case 'conversion':
            charts.push({
                chart_type: 'funnel',
                title: '转化漏斗',
                data_points: [
                    { label: '访问', value: 10000, unit: '人', timestamp: Math.floor(now / 1000) },
                    { label: '注册', value: 2500, unit: '人', timestamp: Math.floor(now / 1000) },
                    { label: '购买', value: 750, unit: '人', timestamp: Math.floor(now / 1000) }
                ],
                metadata: { conversion_rate: '7.5%' }
            });
            break;
        case 'engagement':
            charts.push({
                chart_type: 'bar',
                title: '用户参与度指标',
                data_points: [
                    { label: '平均停留时间', value: 4.5, unit: '分钟', timestamp: Math.floor(now / 1000) },
                    { label: '页面浏览深度', value: 3.2, unit: '页', timestamp: Math.floor(now / 1000) },
                    { label: '互动率', value: 15.8, unit: '%', timestamp: Math.floor(now / 1000) }
                ],
                metadata: { period: '本周' }
            });
            break;
        case 'retention':
            charts.push({
                chart_type: 'line',
                title: '用户留存率',
                data_points: [
                    { label: '第1天', value: 100, unit: '%', timestamp: Math.floor(now / 1000) },
                    { label: '第7天', value: 65, unit: '%', timestamp: Math.floor(now / 1000) },
                    { label: '第30天', value: 35, unit: '%', timestamp: Math.floor(now / 1000) },
                    { label: '第90天', value: 20, unit: '%', timestamp: Math.floor(now / 1000) }
                ],
                metadata: { cohort: '新用户群体' }
            });
            break;
    }

    return charts;
}

function generateInsightsCharts(option) {
    const charts = [];
    const now = Date.now();

    switch(option) {
        case 'trends':
            charts.push({
                chart_type: 'line',
                title: '趋势预测',
                data_points: Array.from({length: 12}, (_, i) => ({
                    label: `未来第${i+1}月`,
                    value: Math.random() * 20000 + 10000,
                    unit: '元',
                    timestamp: Math.floor((now + i * 30 * 24 * 60 * 60 * 1000) / 1000)
                })),
                metadata: { confidence: '85%', model: 'ARIMA' }
            });
            break;
        case 'recommendations':
            charts.push({
                chart_type: 'bar',
                title: '推荐效果',
                data_points: [
                    { label: '点击率提升', value: 25.5, unit: '%', timestamp: Math.floor(now / 1000) },
                    { label: '转化率提升', value: 18.2, unit: '%', timestamp: Math.floor(now / 1000) },
                    { label: '收入提升', value: 32.1, unit: '%', timestamp: Math.floor(now / 1000) }
                ],
                metadata: { algorithm: 'collaborative_filtering' }
            });
            break;
        case 'anomalies':
            charts.push({
                chart_type: 'scatter',
                title: '异常检测结果',
                data_points: [
                    { label: '正常数据', value: 95.2, unit: '%', timestamp: Math.floor(now / 1000) },
                    { label: '轻微异常', value: 3.8, unit: '%', timestamp: Math.floor(now / 1000) },
                    { label: '严重异常', value: 1.0, unit: '%', timestamp: Math.floor(now / 1000) }
                ],
                metadata: { algorithm: 'isolation_forest', threshold: '0.05' }
            });
            break;
        case 'forecasting':
            charts.push({
                chart_type: 'line',
                title: '预测分析',
                data_points: Array.from({length: 6}, (_, i) => ({
                    label: `Q${i+1}`,
                    value: Math.random() * 50000 + 100000,
                    unit: '元',
                    timestamp: Math.floor((now + i * 90 * 24 * 60 * 60 * 1000) / 1000)
                })),
                metadata: { model: 'prophet', accuracy: '92%' }
            });
            break;
    }

    return charts;
}

// 生成汇总指标的函数
function generateAnalyticsMetrics(option) {
    switch(option) {
        case 'sales':
            return {
                '总销售额': 156780,
                '订单数量': 1245,
                '平均客单价': 125.9,
                '同比增长': 15.6
            };
        case 'revenue':
            return {
                '月收入': 234560,
                '毛利率': 45.2,
                '净利润': 89340,
                '增长率': 12.8
            };
        case 'customers':
            return {
                '总客户数': 12450,
                '新增客户': 890,
                '活跃客户': 8760,
                '客户满意度': 4.6
            };
        case 'products':
            return {
                '产品总数': 156,
                '热销产品': 23,
                '库存周转率': 8.5,
                '退货率': 2.1
            };
        default:
            return {};
    }
}

function generateReportsMetrics(option) {
    switch(option) {
        case 'performance':
            return {
                '平均响应时间': 145.6,
                '系统可用性': 99.8,
                'CPU使用率': 65.2,
                '内存使用率': 72.1
            };
        case 'errors':
            return {
                '总错误数': 234,
                '错误率': 0.12,
                '已修复': 198,
                '待处理': 36
            };
        case 'security':
            return {
                '安全事件': 12,
                '威胁等级': 2.3,
                '防护成功率': 98.7,
                '漏洞数量': 3
            };
        case 'usage':
            return {
                '日活用户': 8950,
                '月活用户': 45600,
                '使用时长': 25.6,
                '功能使用率': 78.9
            };
        default:
            return {};
    }
}

function generateStatisticsMetrics(option) {
    switch(option) {
        case 'traffic':
            return {
                '总访问量': 156780,
                '独立访客': 89450,
                '页面浏览量': 345670,
                '跳出率': 35.6
            };
        case 'conversion':
            return {
                '转化率': 7.5,
                '注册转化': 25.0,
                '购买转化': 30.0,
                'ROI': 3.2
            };
        case 'engagement':
            return {
                '平均停留': 4.5,
                '页面深度': 3.2,
                '互动率': 15.8,
                '分享率': 8.9
            };
        case 'retention':
            return {
                '7日留存': 65.0,
                '30日留存': 35.0,
                '90日留存': 20.0,
                '年留存': 12.5
            };
        default:
            return {};
    }
}

function generateInsightsMetrics(option) {
    switch(option) {
        case 'trends':
            return {
                '预测准确率': 85.6,
                '趋势强度': 7.8,
                '置信度': 92.3,
                '预测周期': 12
            };
        case 'recommendations':
            return {
                '推荐精度': 78.9,
                '点击提升': 25.5,
                '转化提升': 18.2,
                '满意度': 4.3
            };
        case 'anomalies':
            return {
                '检测精度': 95.2,
                '误报率': 2.1,
                '异常数量': 15,
                '处理率': 87.5
            };
        case 'forecasting':
            return {
                '预测精度': 92.1,
                '模型得分': 8.7,
                '预测范围': 6,
                '更新频率': 7
            };
        default:
            return {};
    }
}



const port = 48159;

// 启动服务器并初始化protobuf
const startServer = async () => {
    await initProtobufSchema();

    app.listen(port, () => {
        console.log(`Server is running on http://localhost:${port}`);
    });
};

startServer();