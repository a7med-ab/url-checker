
import mongoose from "mongoose";

const LinkSchema =new mongoose.Schema({

    url: {
        type: String,
        required: true,
        default: 0  
    },
    category: {
        type: String,
        required: true,
        default:"unkown"
    },
    number_of_trueVotes:{
        type:Number,
        default:0
    },
    number_of_wrongVotes:{
        type:Number,
        default:0
    },
    date_of_firstSubmession:{
        type:Date,
        default: Date.now
    }
  
})

const LinksModel = mongoose.model("links"/*name of model(table)*/,LinkSchema)//name of the schema
export default LinksModel