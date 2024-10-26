"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const database_1 = require("./database");
const router = express_1.default.Router();
const secretKey = 'your-secret-key'; // Секретный ключ для JWT
// Регистрация
router.post('/register', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { username, password } = req.body;
        const db = yield (0, database_1.openDb)();
        const existingUser = yield db.get('SELECT * FROM users WHERE username = ?', username);
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }
        const hashedPassword = yield bcryptjs_1.default.hash(password, 10);
        yield db.run('INSERT INTO users (username, password) VALUES (?, ?)', username, hashedPassword);
        // Создаем JWT-токен
        const user = yield db.get('SELECT * FROM users WHERE username = ?', username);
        const token = jsonwebtoken_1.default.sign({ userId: user.id }, secretKey, { expiresIn: '10h' });
        res.status(201).json({ message: 'User registered successfully', token });
    }
    catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ message: 'Error registering user' });
    }
}));
// Авторизация
router.post('/login', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { username, password } = req.body;
    const db = yield (0, database_1.openDb)();
    const user = yield db.get('SELECT * FROM users WHERE username = ?', username);
    if (!user) {
        return res.status(400).json({ message: 'Invalid username or password' });
    }
    const isPasswordValid = yield bcryptjs_1.default.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(400).json({ message: 'Invalid username or password' });
    }
    const token = jsonwebtoken_1.default.sign({ userId: user.id }, secretKey, { expiresIn: '10h' });
    res.json({ token, user });
}));
// Middleware для проверки JWT токена
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(403).json({ message: 'Token is required' });
    }
    try {
        const tokenValue = token.split(' ')[1]; // Извлекаем токен из заголовка Authorization
        const decoded = jsonwebtoken_1.default.verify(tokenValue, secretKey); // Проверяем токен
        req.user = decoded; // Декодированная информация (например, userId)
        next();
    }
    catch (error) {
        return res.status(401).json({ message: 'Invalid token' });
    }
};
router.post('/saveUserData', authenticateToken, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const db = yield (0, database_1.openDb)();
        const userData = req.body;
        // Проверяем, существует ли req.user и является ли он объектом JwtPayload
        if (req.user && typeof req.user !== 'string') {
            const userId = req.user.userId; // Приведение req.user к типу JwtPayload
            if (!userId) {
                return res.status(400).json({ message: 'Invalid userId' });
            }
            // Проверяем, существует ли пользователь с таким идентификатором
            const existingUser = yield db.get('SELECT * FROM users WHERE id = ?', [userId]);
            if (existingUser) {
                // Обновляем данные пользователя
                /*         console.log('Executing query with data:', userData);
                        console.log('User:', req.user); */
                yield db.run(`UPDATE users SET 
            name = ?, surName = ?, fathName = ?, birthDate = ?, male = ?, female = ?, tel = ?, email = ?, address = ?, 
            workBookNum = ?, billNum = ?, passNum = ?, issueDate = ?, issuingOrgan = ?, 
            birthPlace = ?, jmbgNum = ?, jmbgFrom = ?, jmbgTo = ?, pib = ?, compName = ?, compAddr = ?, compCity = ?, 
            compMunicipal = ?, compRegNum = ?, compRegDate = ?, compBillNum = ?, 
            famName1 = ?, famPassNum1 = ?, famMember1 = ?, famJmbgNum1 = ?, famName2 = ?, famPassNum2 = ?, famMember2 = ?, 
            famJmbgNum2 = ?, famName3 = ?, famPassNum3 = ?, famMember3 = ?, famJmbgNum3 = ?, famName4 = ?, famPassNum4 = ?, 
            famMember4 = ?, famJmbgNum4 = ?, famName5 = ?, famPassNum5 = ?, famMember5 = ?, famJmbgNum5 = ?,compStreetHome = ?,city = ?
          WHERE id = ?`, [
                    userData.name, userData.surName, userData.fathName, userData.birthDate, userData.male, userData.female,
                    userData.tel, userData.email, userData.address, userData.workBookNum,
                    userData.billNum, userData.passNum, userData.issueDate, userData.issuingOrgan,
                    userData.birthPlace, userData.jmbgNum, userData.jmbgFrom, userData.jmbgTo, userData.pib, userData.compName,
                    userData.compAddr, userData.compCity, userData.compMunicipal,
                    userData.compRegNum, userData.compRegDate, userData.compBillNum, userData.famName1, userData.famPassNum1,
                    userData.famMember1, userData.famJmbgNum1, userData.famName2, userData.famPassNum2, userData.famMember2,
                    userData.famJmbgNum2, userData.famName3, userData.famPassNum3, userData.famMember3, userData.famJmbgNum3,
                    userData.famName4, userData.famPassNum4, userData.famMember4, userData.famJmbgNum4, userData.famName5,
                    userData.famPassNum5, userData.famMember5, userData.famJmbgNum5, userData.compStreetHome, userData.city, userId
                ]);
                res.json({ message: ' data updated successfully' });
            }
            else {
                res.status(404).json({ message: 'User not found' });
            }
        }
        else {
            res.status(401).json({ message: 'Unauthorized' });
        }
    }
    catch (error) {
        console.error('Error saving user data:', error);
        res.status(500).json({ message: 'Error saving user data' });
    }
}));
// Маршрут для получения всех данных пользователей
router.get('/getAllUsers', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const db = yield (0, database_1.openDb)();
        const users = yield db.all('SELECT * FROM users'); // Получаем всех пользователей
        res.json(users); // Возвращаем результат в виде JSON
    }
    catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ message: 'Error fetching users' });
    }
}));
exports.default = router;
