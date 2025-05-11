import express from "express"
import cookieParser from "cookie-parser"
import dotenv from "dotenv"
import cors from "cors"
import { timeStamp } from "console";
import { connect } from "http2";


const app = express();
dotenv.config();

app.use(express.json()); //parses json type date from client and make it available in req.body
app.use(express.urlencoded());//parses url (String,arrays)
app.use(cookieParser());

const PORT = process.env.PORT;
app.use(cors({
    origin: ["http://127.0.0.1:6000", 
    // "http://localhost:3000", "http://localhost:5500",



        // "https://pdf-tkf.vercel.app"
 
     ],
     credentials: true,
     methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
     allowedHeaders: ['Content-Type','Authorisation']
}))

app.get("/healthCheck",(req,res)=>{
    res.status(200).json({
        message:"App is running ",
        timestamp:new Date().toISOString();
    })
})


app.listen(PORT,(req,res)=>{
    console.log(`Application is running at port : ${PORT}`);
    connectDB();
})

