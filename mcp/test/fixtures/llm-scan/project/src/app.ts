import express from 'express';
import { requireAuth } from './middleware/auth.js';
import { adminRouter } from './routes/admin.js';
import { filesRouter } from './routes/files.js';
import { usersRouter } from './routes/users.js';

export const app = express();

app.use(express.json());
app.use('/users', requireAuth, usersRouter);
app.use('/files', requireAuth, filesRouter);
app.use('/admin', adminRouter);

app.listen(Number(process.env.PORT ?? 3000));
