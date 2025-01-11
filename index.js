import express from 'express';
import connectionDB from './db/connection.js';
import userRoutes from './controllers/users.routes.js';

const app = express();
connectionDB()
// Middleware
app.use(express.json());

// Routes

app.use('/api/users', userRoutes);
app.get('/',(req,res)=>{
res.json({msg:"welcome !"})
})
// Error handling middleware
app.use((err, req, res,next) => {

  if (err) return res.status(err.statuscode).json({ message: err.message });
});




// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

