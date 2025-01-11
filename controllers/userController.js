import userModel from "../db/models/users.js";
import LinksModel from "../db/models/links.js"
import ApprovalRequestModel from "../db/models/approvalRequests.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken"; 
import { promisify } from 'node:util';
import nodemailer from "nodemailer"
import { handleAsync } from "../utilities/handlingAsync.js";
import appError from "../utilities/appError.js";
const verifyToken = promisify(jwt.verify).bind(jwt);

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: '202102703@pua.edu.eg',
        pass: 'pwmj sdjy zdtq xgof'
    }
});

const saltRounds = 5;

const primaryAdminEmail = "primaryAdmin@gmail.com";
//------------------------------------------------------------------------
//------------------------------------------------------------------------
export const signup = handleAsync (async (req, res,next) => {
    try {
        const { name, email, password } = req.body;
        const userExist = await userModel.findOne({ email });
        if (userExist) {
            res.send({ msg: "User already exists" });
        } else {
            const hash = bcrypt.hashSync(password, saltRounds);
            await userModel.create({ email, password: hash, name });
            res.send({ msg: "done" });
        }
    } catch (error) {
        res.send({ msg: "error", error: error.message });
    }
})
//------------------------------------------------------------------------
//------------------------------------------------------------------------

export const forgetPassword = handleAsync (async (req, res,next) => {
    try {
        const { email } = req.body;
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.send({ msg: "User not found" });
        }
        // Generate reset token
        const resetToken = jwt.sign({ email: user.email }, 'a7med', { expiresIn: '30m' });
        // Send email with reset link
        let mailOptions = {
            from: 'تطبيق فحص الروابط',
            to: user.email,
            subject: 'Password Reset',
            html: `
                <p>اضغط على الرابط لتغيير رقمك السري. ملحوظة: سينتهي صلاحية الرابط بعد 30 دقيقة.</p>
                <p><a href="http://localhost:3000/resetPassword?token=${resetToken}">تغيير رقمك السري</a></p>
            `
        };
        
        await transporter.sendMail(mailOptions);
        res.send({ msg: "Reset email sent" });
    } catch (error) {
        res.send({ msg: "Internal server error", error: error.message });
    }
})

//------------------------------------------------------------------------
//------------------------------------------------------------------------
export const login = handleAsync (async (req, res,next) => {//users & admin
    try {
        const { email, password } = req.body;
        const user = await userModel.findOne({ email });
        if (!user) {
           return next(new appError("user not exist",404))
        }
        const isLogged = bcrypt.compareSync(password, user.password);
        if (!isLogged) {
            res.send({ msg: "Invalid credentials" });
        }
        if (email === primaryAdminEmail) {
            await userModel.updateOne({ email }, { $set: { role: "admin" } });
        }
        
        const updatedUser = await userModel.findOne({ email });
        // Generate token with email and role
        const token = jwt.sign(
            { email: updatedUser.email, role: updatedUser.role },
            'a7med',
            { expiresIn: '10h' }
        );
        return res.send({ msg: `Logged in successfully, hi ${updatedUser.name}`, token });
    } catch (error) {
       return res.send({ msg: "Internal server error", error: error.message });
    }
})
//------------------------------------------------------------------------
//------------------------------------------------------------------------

export const resetPassword = handleAsync(async (req, res, next) => {
    try {
        const { newPassword } = req.body;
        const bearerHeader = req.headers['authorization'];

        if (!bearerHeader) {
            return next(new appError("No token provided. Please sign in again.", 404));
        }

        const bearer = bearerHeader.trim().split(' ');
        const token = bearer[1];
        const decoded = jwt.verify(token, 'a7med');
        const email = decoded.email;

        const user = await userModel.findOne({ email });
        if (!user) {
            return res.send({ msg: "User does not exist" });
        }

        
        const hashedPassword = bcrypt.hashSync(newPassword, saltRounds);

        await userModel.findOneAndUpdate({ email }, { $set: { password: hashedPassword } });
        res.send({ msg: "Password reset successfully" });
    } catch (error) {
        console.error('Error:', error);
        return res.send({ msg: "Internal server error", error: error.message });
    }
});

//----------------------------------------------------
export const changePermission = handleAsync (async (req, res,next) => {//admin
    try {
        const bearerHeader = req.headers['authorization'];
        const { user_email } = req.body;

        if (!bearerHeader) {
            return next(new appError("No token provided. Please sign in again.", 404));////for front end when this appear return the user to the api of login to generate a new token
        }

        const bearer = bearerHeader.trim().split(' ');
        const token = bearer[1];

        const decoded = await verifyToken(token, 'a7med');

        if (decoded.role !== "admin") {
            return next(new appError("No token provided. Please sign in again.", 403));
        }

        const user = await userModel.findOne({ email: user_email });

        if (!user) {
            return res.send({ msg: ' user not exist' });
        }

        await userModel.findOneAndUpdate({ email: user_email }, { $set: { role: "admin" } }, { new: true });

        res.send({ msg: 'Permission changed successfully' });
    } catch (err) {
        return next(new appError("error",404),err.message)
    }
})
//------------------------------------------------------------------------
//------------------------------------------------------------------------
export const addLink = handleAsync (async (req, res,next) => { //admin
    const number_of_trueVotes=0
    const number_of_wrongVotes=0
    try {
        const bearerHeader = req.headers['authorization'];
        const { url,category, } = req.body;

        if (!bearerHeader) {
            return res.send({ msg: 'No token provided' });
        }

        const bearer = bearerHeader.trim().split(' ');
        const token = bearer[1];

        const decoded = await verifyToken(token, 'a7med');

        if (decoded.role !== "admin") {
            return next(new appError("unauthorized user",403))
        }

        await LinksModel.create({url,category,number_of_trueVotes,number_of_wrongVotes})
        return res.send({ msg: 'url added succesfully as :',category });
        //logic here 

    } catch (err) {
        return next(new appError("error unavailable url try again",404),err.message)
    }
})
//-----------------------------------------------------------------
export const seeRequests = handleAsync (async (req, res,next) => { //admin
    
    try {
        const bearerHeader = req.headers['authorization'];
        

        if (!bearerHeader) {
            return res.send({ msg: 'No token provided' });
        }

        const bearer = bearerHeader.trim().split(' ');
        const token = bearer[1];

        const decoded = await verifyToken(token, 'a7med');

        if (decoded.role !== "admin") {
            return next(new appError("unAuthorized Access", 403));
        }

        const requests = await ApprovalRequestModel.find(); // Populate user email 
        if (!requests || requests.length === 0) 
            { return res.status(404).json({ msg: 'No requests found' }); }
         return res.json({ msg: 'All requests', requests });
        //logic here 

    } catch (err) {
        return next(new appError("error",500),err.message)
    }
})
//------------------------------------------------
export const editCattegory = handleAsync (async (req, res,next) => { //admin
   
    try {
        const bearerHeader = req.headers['authorization'];
        const { url,category} = req.body;

        if (!bearerHeader) {
            return next(new appError("no token please sign in again",404))
        }

        const bearer = bearerHeader.trim().split(' ');
        const token = bearer[1];

        const decoded = await verifyToken(token, 'a7med');

        if (decoded.role !== "admin") {
            return next(new appError("unauthorized",403
            ))
        }

        await LinksModel.findOneAndUpdate({url},{ $set: { category: category } }, { new: true })
        return res.send({ msg: 'url edited succesfully as :',category });
        //logic here 

    } catch (err) {
        return next(new appError("error",500),err.message)
    }
})
//------------------------------------
export const getWrongReports = handleAsync (async (req, res,next) => { //admin
   
    try {
        const bearerHeader = req.headers['authorization'];
        

        if (!bearerHeader) {
            return next(new appError("no token please sign in again",404))
        }

        const bearer = bearerHeader.trim().split(' ');
        const token = bearer[1];

        const decoded = await verifyToken(token, 'a7med');

        if (decoded.role !== "admin") {
            return next(new appError("unauthorized",403))
        }

      const results =  await LinksModel.find({})
    
      const falseReports = results.filter(link => 
        link.number_of_wrongVotes > 0
      );

      let mailOptions = {
        from: 'تطبيق فحص الروابط',
        to: decoded.email,
        subject: 'الروابط تم التصويت عليها ان نتاجءها خاطءه',
        html: `
            ,<p> links : ${falseReports}
        `
    };
    
    await transporter.sendMail(mailOptions);
        return res.send({ msg: 'these reports highlited as false reports :',falseReports });
        
        //logic here 

    } catch (err) {
        return next(new appError("internal err",500
        ))
    }
})