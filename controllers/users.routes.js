import { Router} from "express";
import * as uc from "./userController.js"
import * as uf from "./userFeaturesController.js"



const router = Router()




router.post('/signup',uc.signup)
router.post('/login',uc.login)
router.post('/permession_change',uc.changePermission)
router.post('/add_link',uc.addLink)
router.post('/link_check',uf.checkLink)
router.post('/report_result/:url/:status',uf.reportResult)
router.post('/sendRequest',uf.createApprovalRequest)
router.get('/readRequests',uc.seeRequests)
router.put('/editCategory',uc.editCattegory)
router.post('/sendEmail',uc.forgetPassword)
router.post('/resetPassword',uc.resetPassword)
router.get('/getWrongReports',uc.getWrongReports)

export default router;



