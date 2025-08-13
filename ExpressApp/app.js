import express from 'express';
import mongoose from 'mongoose';
import { configDotenv } from 'dotenv';
import http from 'http';
import userRouter from './routes/user.js';
import fileRouter from './routes/file.js';
import cors from 'cors';
import commentRouter from './routes/comment.js';
import helmet from 'helmet'; // Import helmet

configDotenv();

const app = express();
app.use(express.json());

// Block access to hidden files 
app.use((req, res, next) => {
  if (/\/\.[^\/]+/.test(req.url)) {
    return res.status(403).send('Access Denied');
  }
  next();
});

// Apply helmet with CSP configuration
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "http://localhost:5173"],
        styleSrc: ["'self'", "'unsafe-inline'", "http://localhost:5173"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'", "http://localhost:5173"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"]  // Prevent embedding in iframes (ClickJacking protection)
      },
    },
    frameguard: {
      action: 'deny'  // Set X-Frame-Options: DENY header for ClickJacking protection
    }
  })
);

// Explicitly add noSniff to prevent MIME type sniffing
app.use(helmet.noSniff());

const corsOptions = {
  origin: 'http://localhost:5173',
  optionsSuccessStatus: 200 // For legacy browser support
};

app.use(cors(corsOptions));

app.use('/user', userRouter);
app.use('/file', fileRouter);
app.use('/comment', commentRouter);

const server = http.createServer(app);

console.log(`${process.env.DB_URL}/${process.env.DATABASE_NAME}`)

mongoose.connect(`${process.env.DB_URL}/${process.env.DATABASE_NAME}`)
.then(() => {
    server.listen(3000, () => {
        console.log("server started at port 3000");
    })
})
.catch((err) => {
    console.log(`ERROR: ${err}`);
})