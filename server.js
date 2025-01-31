const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const {join} = require("node:path"); // 使用 crypto-js 库

// 设置静态文件目录
app.use(express.static(join(__dirname, 'public')));
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());



const port = 10086;
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});