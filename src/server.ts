import express from 'express';
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken';
import { openDb } from './database';
import bodyParser, { json } from 'body-parser';
import { Request, Response, NextFunction } from 'express';
import { JwtPayload } from 'jsonwebtoken';
import { Jwt } from 'jsonwebtoken';
import dotenv from 'dotenv';
import { randomBytes } from 'crypto';


dotenv.config();


declare module 'express-serve-static-core' {
  interface Request {
    user?: string | JwtPayload; // Добавляем поле user
  }
}


const router = express.Router();
const secretKey = 'JNSDsdfjvjse234djsdpnp345892xzdfhydyk34234';


router.get('/', (req, res) => {
/*   console.log('Request body:', req.body); */
  res.send('server is wokr');
});

// Регистрация



router.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
/*     console.log('gogo staert register'); */
    const db = await openDb();
    const existingUser = await db.get('SELECT * FROM users WHERE username = ?', username);

    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.run('INSERT INTO users (username, password) VALUES (?, ?)', username, hashedPassword);

    // Создаем JWT-токен
    const user = await db.get('SELECT * FROM users WHERE username = ?', username);
    const token = jwt.sign({ userId: user.id, userRole: user.role }, secretKey, { expiresIn: '10h' });

    res.status(201).json({ message: 'User registered successfully', token });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ message: 'Error registering user' });
  }
});


// Авторизация
router.post('/login', async (req, res) => { 
  console.log('Request body:', req.body);
  const { username, password } = req.body;

  const db = await openDb();
  const user = await db.get('SELECT * FROM users WHERE username = ?', username);
/*   console.log('User from DB:', user); */

  if (!user) {
    console.log('Invalid username');
    return res.status(400).json({ message: 'Invalid username or password' });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  console.log('Password valid:', isPasswordValid);

  if (!isPasswordValid) {
    console.log('Invalid password');
    return res.status(400).json({ message: 'Invalid username or password' });
  }

  const token = jwt.sign({ userId: user.id, userRole:user.role }, secretKey, { expiresIn: '10h' });
  console.log('Login successful, token generated');
  res.json({ token, user });
});





// Middleware для проверки JWT токена
const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  console.log('JWT_SECRET:', process.env.JWT_SECRET);
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    console.log('Authorization header is missing');
    return res.status(403).json({ message: 'Token is required' });
  }

  const tokenValue = authHeader.split(' ')[1];
  if (!tokenValue) {
    console.log('Token value is missing in Authorization header');
    return res.status(403).json({ message: 'Token is required' });
  }

  try {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      throw new Error('JWT_SECRET is not defined');
    }

    const decoded = jwt.verify(tokenValue, secret) as JwtPayload;
    console.log('Decoded token:', decoded);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('JWT verification error:', error);
    return res.status(401).json({ message: 'Invalid token' });
  }
};

function generateRandomString(length: number) {
  return randomBytes(length).toString('hex').slice(0, length);
}

router.post('/handleCreateUser', async (req: Request, res: Response) => {
  try {
    const db = await openDb();
    const userData = req.body;
    const { username, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    /* console.log('Saving to DB:', { username, password }); */
    await db.run(
      `INSERT INTO users 
        (username, password, name, surName, fathName, birthDate, male, female, tel, email, address, 
         workBookNum, billNum, passNum, issueDate, issuingOrgan, birthPlace, jmbgNum, jmbgFrom, jmbgTo, 
         pib, compName, compAddr, compCity, compMunicipal, compRegNum, compRegDate, compBillNum, 
         famName1, famPassNum1, famMember1, famJmbgNum1, famName2, famPassNum2, famMember2, famJmbgNum2, 
         famName3, famPassNum3, famMember3, famJmbgNum3, famName4, famPassNum4, famMember4, famJmbgNum4, 
         famName5, famPassNum5, famMember5, famJmbgNum5, compStreetHome, city, mailIndex, compMailIndex, 
         bankName, billType, educLevel = ?, educTypeDoc = ?, educNameOrg = ?, educDateReciveDoc = ?, educPlaceAndCountryReciveDoc = ?) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
               ?, ?, ?, ?, ?, ?, ?, ?, ?, 
               ?, ?, ?, ?, ?, ?, ?, ?, 
               ?, ?, ?, ?, ?, ?, ?, ?, 
               ?, ?, ?, ?, ?, ?, ?, ?, 
               ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?,?,?,?)`,
      [
        username, hashedPassword, userData.name, userData.surName, userData.fathName, userData.birthDate, userData.male, 
        userData.female, userData.tel, userData.email, userData.address, userData.workBookNum, userData.billNum, 
        userData.passNum, userData.issueDate, userData.issuingOrgan, userData.birthPlace, userData.jmbgNum, 
        userData.jmbgFrom, userData.jmbgTo, userData.pib, userData.compName, userData.compAddr, userData.compCity, 
        userData.compMunicipal, userData.compRegNum, userData.compRegDate, userData.compBillNum, userData.famName1, 
        userData.famPassNum1, userData.famMember1, userData.famJmbgNum1, userData.famName2, userData.famPassNum2, 
        userData.famMember2, userData.famJmbgNum2, userData.famName3, userData.famPassNum3, userData.famMember3, 
        userData.famJmbgNum3, userData.famName4, userData.famPassNum4, userData.famMember4, userData.famJmbgNum4, 
        userData.famName5, userData.famPassNum5, userData.famMember5, userData.famJmbgNum5, userData.compStreetHome, 
        userData.city, userData.mailIndex, userData.compMailIndex, userData.bankName, userData.billType,
        userData.educLevel, userData.educTypeDoc ,userData.educNameOrg ,userData.educDateReciveDoc ,userData.educPlaceAndCountryReciveDoc
      ]
    );
    

    res.status(201).json({ message: 'Пользователь создан'});

  } catch (error) {
    console.error('Ошибка при создании пользователя:', error);
    res.status(500).json({ error: 'Ошибка при создании пользователя' });
  }
});


router.post('/saveSubUserData', async (req: Request, res: Response) => {
  try {
    const db = await openDb(); 
    const userData = req.body;

    
      const userId = userData.id; // id напрямую из принимаемого userData на фронте доступна только для админов

      if (!userId) {
        return res.status(400).json({ message: 'Invalid userId or id not recieved' });
      }

      // Проверяем, существует ли пользователь с таким идентификатором
      const existingUser = await db.get('SELECT * FROM users WHERE id = ?', [userId]);

      if (existingUser) {

        await db.run(
          `UPDATE users SET 
            name = ?, surName = ?, fathName = ?, birthDate = ?, male = ?, female = ?, tel = ?, email = ?, address = ?, 
            workBookNum = ?, billNum = ?, passNum = ?, issueDate = ?, issuingOrgan = ?, 
            birthPlace = ?, jmbgNum = ?, jmbgFrom = ?, jmbgTo = ?, pib = ?, compName = ?, compAddr = ?, compCity = ?, 
            compMunicipal = ?, compRegNum = ?, compRegDate = ?, compBillNum = ?, 
            famName1 = ?, famPassNum1 = ?, famMember1 = ?, famJmbgNum1 = ?, famName2 = ?, famPassNum2 = ?, famMember2 = ?, 
            famJmbgNum2 = ?, famName3 = ?, famPassNum3 = ?, famMember3 = ?, famJmbgNum3 = ?, famName4 = ?, famPassNum4 = ?, 
            famMember4 = ?, famJmbgNum4 = ?, famName5 = ?, famPassNum5 = ?, famMember5 = ?, famJmbgNum5 = ?,compStreetHome = ?,
            city = ?, mailIndex = ?, compMailIndex = ?, bankName = ?, billType = ?,
            educLevel = ?, educTypeDoc = ?, educNameOrg = ?, educDateReciveDoc = ?, educPlaceAndCountryReciveDoc = ?
          WHERE id = ?`,
          [
            userData.name, userData.surName, userData.fathName, userData.birthDate, userData.male, userData.female, 
            userData.tel, userData.email, userData.address, userData.workBookNum, 
            userData.billNum, userData.passNum, userData.issueDate, userData.issuingOrgan, 
            userData.birthPlace, userData.jmbgNum, userData.jmbgFrom, userData.jmbgTo, userData.pib, userData.compName, 
            userData.compAddr, userData.compCity, userData.compMunicipal, 
            userData.compRegNum, userData.compRegDate, userData.compBillNum, userData.famName1, userData.famPassNum1, 
            userData.famMember1, userData.famJmbgNum1, userData.famName2, userData.famPassNum2, userData.famMember2, 
            userData.famJmbgNum2, userData.famName3, userData.famPassNum3, userData.famMember3, userData.famJmbgNum3, 
            userData.famName4, userData.famPassNum4, userData.famMember4, userData.famJmbgNum4, userData.famName5, 
            userData.famPassNum5, userData.famMember5, userData.famJmbgNum5,userData.compStreetHome,userData.city,
            userData.mailIndex,userData.compMailIndex,userData.bankName,userData.billType,
            userData.educLevel, userData.educTypeDoc ,userData.educNameOrg ,userData.educDateReciveDoc ,userData.educPlaceAndCountryReciveDoc, userId
          ]
        );
        
        res.json({ message: ' data updated successfully' });
      } else {
        res.status(404).json({ message: 'User not found' });
      }
  } catch (error) {
    console.error('Error saving user data:', error);
    res.status(500).json({ message: 'Error saving user data' });
  }
});




router.post('/saveUserData', authenticateToken, async (req: Request, res: Response) => {
  try {
    const db = await openDb(); 
    const userData = req.body;
    // Проверяем, существует ли req.user и является ли он объектом JwtPayload
    if (req.user && typeof req.user !== 'string') {
      const userId = (req.user as JwtPayload).userId; // Приведение req.user к типу JwtPayload

      if (!userId) {
        return res.status(400).json({ message: 'Invalid userId' });
      }

      // Проверяем, существует ли пользователь с таким идентификатором
      const existingUser = await db.get('SELECT * FROM users WHERE id = ?', [userId]);

      if (existingUser) {

        await db.run(
          `UPDATE users SET 
            name = ?, surName = ?, fathName = ?, birthDate = ?, male = ?, female = ?, tel = ?, email = ?, address = ?, 
            workBookNum = ?, billNum = ?, passNum = ?, issueDate = ?, issuingOrgan = ?, 
            birthPlace = ?, jmbgNum = ?, jmbgFrom = ?, jmbgTo = ?, pib = ?, compName = ?, compAddr = ?, compCity = ?, 
            compMunicipal = ?, compRegNum = ?, compRegDate = ?, compBillNum = ?, 
            famName1 = ?, famPassNum1 = ?, famMember1 = ?, famJmbgNum1 = ?, famName2 = ?, famPassNum2 = ?, famMember2 = ?, 
            famJmbgNum2 = ?, famName3 = ?, famPassNum3 = ?, famMember3 = ?, famJmbgNum3 = ?, famName4 = ?, famPassNum4 = ?, 
            famMember4 = ?, famJmbgNum4 = ?, famName5 = ?, famPassNum5 = ?, famMember5 = ?, famJmbgNum5 = ?,compStreetHome = ?,city = ?,
            mailIndex = ?, compMailIndex = ?, bankName = ?, billType = ?,
            educLevel = ?, educTypeDoc = ?, educNameOrg = ?, educDateReciveDoc = ?, educPlaceAndCountryReciveDoc = ?
          WHERE id = ?`,
          [
            userData.name, userData.surName, userData.fathName, userData.birthDate, userData.male, userData.female, 
            userData.tel, userData.email, userData.address, userData.workBookNum, 
            userData.billNum, userData.passNum, userData.issueDate, userData.issuingOrgan, 
            userData.birthPlace, userData.jmbgNum, userData.jmbgFrom, userData.jmbgTo, userData.pib, userData.compName, 
            userData.compAddr, userData.compCity, userData.compMunicipal, 
            userData.compRegNum, userData.compRegDate, userData.compBillNum, userData.famName1, userData.famPassNum1, 
            userData.famMember1, userData.famJmbgNum1, userData.famName2, userData.famPassNum2, userData.famMember2, 
            userData.famJmbgNum2, userData.famName3, userData.famPassNum3, userData.famMember3, userData.famJmbgNum3, 
            userData.famName4, userData.famPassNum4, userData.famMember4, userData.famJmbgNum4, userData.famName5, 
            userData.famPassNum5, userData.famMember5, userData.famJmbgNum5,userData.compStreetHome,userData.city,
            userData.mailIndex,userData.compMailIndex,userData.bankName,userData.billType,
            userData.educLevel, userData.educTypeDoc ,userData.educNameOrg ,userData.educDateReciveDoc ,userData.educPlaceAndCountryReciveDoc,  userId
          ]
        );
        
        res.json({ message: ' data updated successfully' });
      } else {
        res.status(404).json({ message: 'User not found' });
      }
    } else {
      res.status(401).json({ message: 'Unauthorized' });
    }
  } catch (error) {
    console.error('Error saving user data:', error);
    res.status(500).json({ message: 'Error saving user data' });
  }
});


router.post ('/saveSubmissionUser',authenticateToken, async (req:Request,res:Response)=>{
  try{
    const db = await openDb();
    const {submissiveUsername, submissivePassword} = req.body;
    if (!submissiveUsername || !submissivePassword) {
      return res.status(400).json({ message: 'Invalid input' });
    }
    const userId=(req.user as JwtPayload).userId
    if (!userId) {
      return res.status(400).json({ message: 'Invalid userId' });
    }
    const existingUser = await db.get('SELECT * FROM users WHERE id = ?',[userId])
    if (!existingUser){
      return res.status(404).json({message:'User not found'})
    }
    const currentSubmissiveUsers = JSON.parse(existingUser.submissiveUsers || '[]');
    
    if (currentSubmissiveUsers.includes(submissiveUsername)==true){
      return res.status(404).json({message:'user is already a submissive'})
    }

    currentSubmissiveUsers.push(submissiveUsername);

    await db.run(
      `UPDATE users SET submissiveUsers = ? WHERE id = ?`,
      [JSON.stringify(currentSubmissiveUsers), userId]
    );

    return res.json({ message: 'User добавлен успешно' });
  } catch (error) {
    console.error('Error saving user', error);
    return res.status(500).json({ message: 'Error saving user' });
  }
});

interface DecodedToken extends JwtPayload {
  role: string;
  id:number;
}

router.get('/getSubmissiveUsers', authenticateToken, async (req: Request, res: Response) => {
  try {
    const db = await openDb();
    const userId = (req.user as JwtPayload).userId;
    const user = await db.get('SELECT submissiveUsers, role FROM users WHERE id = ?', [userId]);
/*     console.log('Authorization Header:', req.headers['authorization']); */
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Проверка роли
    if (user.role !== 'admin') {
      return res.status(403).json({ message: 'Permission denied: Not an admin.' });
    }

    const submissiveUsers = user.submissiveUsers ? JSON.parse(user.submissiveUsers) : [];
    if (submissiveUsers.length === 0) {
      return res.json([]); // Возвращаем пустой массив
    }

    const placeholders = submissiveUsers.map(() => '?').join(',');
    const submissiveUsersData = await db.all(
      `SELECT * FROM users WHERE username IN (${placeholders})`,
      submissiveUsers
    );

    res.json(submissiveUsersData);
  } catch (error) {
    console.error('Error fetching submissive users:', error);
    res.status(500).json({ message: 'Error fetching submissive users' });
  }
});


 
// Маршрут для получения всех данных пользователей
router.get('/getAllUsers', async (req, res) => {
  try {
/*     console.log('Request GetAll body:', req.body);
    console.log('Request GetAll headers:', req.headers);  */
    const db = await openDb();
    const users = await db.all('SELECT * FROM users'); // Получаем всех пользователей
    res.json(users); // Возвращаем результат в виде JSON
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Error fetching users' });
  }
});



export default router;

