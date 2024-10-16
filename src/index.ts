import express from 'express';
import authRoutes from './server';
import cors from 'cors';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
    origin: 'http://localhost:3000', 
    credentials: true,
  }));

app.use(express.json());
app.use('/server', authRoutes);

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
