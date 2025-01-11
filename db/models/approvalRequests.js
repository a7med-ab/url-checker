import mongoose from "mongoose";

const ApprovalRequestSchema = new mongoose.Schema({
  
  email: {
    type:String,
    required: true,
    unique:true
  },
 
  requestDate: {
    type: Date,
    default: Date.now
  },
  
  approvalStatus: {
    type: String,
    enum: ['Pending', 'Approved', 'Rejected','no action'],
    default: 'no action'
  }
});


const ApprovalRequestModel = mongoose.model('approvalrequests', ApprovalRequestSchema);

export default ApprovalRequestModel;