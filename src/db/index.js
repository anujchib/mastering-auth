import { error } from "console";
import mongoose from "mongoose";

const connectDB = async()=>{

mongoose.connect(process.env.MONGOOSE_URL)

.then(()=>{
    console.log("DataBase Connected Successfully");
})
.catch((error)=>{
    console.log("error connecting database",error);
})
}

export default connectDB

