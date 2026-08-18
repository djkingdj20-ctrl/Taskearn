const express=require('express');
const session=require('express-session');
const app=express();
app.use(express.json());
app.use(express.static('public'));
app.use(session({secret:process.env.SESSION_SECRET||'change-this-secret',resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'lax'}}));

const users=[
 {id:1,name:'Demo User',email:'user@taskearn.demo',password:'123456',role:'user',balance:0,completed:0},
 {id:2,name:'Admin',email:'admin@taskearn.demo',password:'admin123',role:'admin',balance:0,completed:0}
];
const tasks=[
 {id:1,title:'Watch a sponsored video',description:'Watch the complete licensed sponsor video.',type:'Watch',reward:8},
 {id:2,title:'Visit a sponsor page',description:'Open the sponsor page and confirm one simple detail.',type:'Visit',reward:5},
 {id:3,title:'Daily check-in',description:'Open the app and claim today’s check-in.',type:'Check-in',reward:2},
 {id:4,title:'Test a mobile website',description:'Tap two buttons and report whether they work.',type:'Testing',reward:20},
 {id:5,title:'Read a short description',description:'Read a short product description and select its category.',type:'Content',reward:6}
];
const completed=new Set(), withdrawals=[];

function auth(req,res,next){if(!req.session.user)return res.status(401).json({error:'Login required'});next();}
function admin(req,res,next){if(!req.session.user||req.session.user.role!=='admin')return res.status(403).json({error:'Admin only'});next();}

app.get('/api/me',(req,res)=>res.json(req.session.user||null));
app.post('/api/login',(req,res)=>{
 const u=users.find(x=>x.email===req.body.email&&x.password===req.body.password);
 if(!u)return res.status(401).json({error:'Invalid login'});
 req.session.user={id:u.id,name:u.name,email:u.email,role:u.role};
 res.json(req.session.user);
});
app.post('/api/register',(req,res)=>{
 if(!req.body.name||!req.body.email||!req.body.password)return res.status(400).json({error:'All fields required'});
 if(users.some(x=>x.email===req.body.email))return res.status(400).json({error:'Email already exists'});
 const u={id:users.length+1,name:req.body.name,email:req.body.email,password:req.body.password,role:'user',balance:0,completed:0};
 users.push(u); req.session.user={id:u.id,name:u.name,email:u.email,role:u.role}; res.json(req.session.user);
});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/tasks',(req,res)=>res.json(tasks));
app.get('/api/wallet',auth,(req,res)=>{
 const u=users.find(x=>x.id===req.session.user.id);
 res.json({balance:u.balance,completed:u.completed,withdrawals:withdrawals.filter(x=>x.userId===u.id)});
});
app.post('/api/tasks/:id/complete',auth,(req,res)=>{
 const id=Number(req.params.id),u=users.find(x=>x.id===req.session.user.id),t=tasks.find(x=>x.id===id);
 if(!t)return res.status(404).json({error:'Task not found'});
 const key=u.id+':'+id;
 if(completed.has(key))return res.status(400).json({error:'Task already completed in this demo'});
 completed.add(key);u.balance+=t.reward;u.completed++;
 res.json({reward:t.reward});
});
app.post('/api/withdraw',auth,(req,res)=>{
 const u=users.find(x=>x.id===req.session.user.id),amount=Number(req.body.amount);
 if(amount<100)return res.status(400).json({error:'Minimum withdrawal is ₹100'});
 if(amount>u.balance)return res.status(400).json({error:'Insufficient balance'});
 u.balance-=amount;withdrawals.push({id:withdrawals.length+1,userId:u.id,name:u.name,amount,method:req.body.method||'UPI',status:'pending'});
 res.json({ok:true});
});
app.get('/api/admin/stats',admin,(req,res)=>res.json({users:users.length,tasks:tasks.length,pending:withdrawals.filter(x=>x.status==='pending').length}));
app.get('/api/admin/withdrawals',admin,(req,res)=>res.json(withdrawals));
app.post('/api/admin/withdrawals/:id',admin,(req,res)=>{
 const w=withdrawals.find(x=>x.id===Number(req.params.id)); if(!w)return res.status(404).json({error:'Not found'});
 w.status=req.body.status;res.json({ok:true});
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(TaskEarn running on port ${PORT});
});
