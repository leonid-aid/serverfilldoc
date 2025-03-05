import express from 'express';
import authRoutes from './server';
import cors from 'cors';

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors({
    origin: '*', 
    credentials: true,
  }));

app.use(express.json());
app.use('/', authRoutes);

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
