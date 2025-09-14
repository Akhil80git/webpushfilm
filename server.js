require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const webpush = require('web-push');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(bodyParser.json());
app.use(cors());
app.use(express.static(path.join(__dirname))); // serve index.html and sw.js

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret';

// Setup web-push VAPID
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;
if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
  console.error('VAPID keys missing. Generate using: npx web-push generate-vapid-keys');
  process.exit(1);
}
webpush.setVapidDetails('mailto:admin@yourdomain.com', VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(()=> console.log('MongoDB connected'))
  .catch(err => { console.error('MongoDB connection error:', err); process.exit(1); });

// Schemas
const userSchema = new mongoose.Schema({
  name: String,
  email: { type:String, unique:true, required:true },
  passwordHash: String,
  isOwner: { type:Boolean, default:false },
  notify: { type:Boolean, default:false } // whether user turned notifications ON
});

const subscriptionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  subscription: { type: Object } // the push subscription object
});

const User = mongoose.model('User', userSchema);
const Subscription = mongoose.model('Subscription', subscriptionSchema);

// On server start, ensure owner exists (from .env)
(async function ensureOwner(){
  const ownerEmail = process.env.OWNER_EMAIL;
  const ownerPass = process.env.OWNER_PASSWORD;
  if (!ownerEmail || !ownerPass) {
    console.error('OWNER_EMAIL or OWNER_PASSWORD not set in .env');
    process.exit(1);
  }
  let owner = await User.findOne({ email: ownerEmail });
  if (!owner) {
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(ownerPass, salt);
    owner = new User({ email: ownerEmail, passwordHash: hash, name: 'Owner', isOwner: true, notify: true });
    await owner.save();
    console.log('Owner account created with email:', ownerEmail);
  } else {
    if (!owner.isOwner) {
      owner.isOwner = true;
      await owner.save();
      console.log('Existing user marked as owner.');
    } else {
      console.log('Owner exists.');
    }
  }
})();

// Helpers
function authMiddleware(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error:'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch(e) {
    return res.status(401).json({ error:'Invalid token' });
  }
}

// Routes

// Register (for normal users) — block if trying to register owner email
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error:'Missing fields' });

    if (email === process.env.OWNER_EMAIL) {
      return res.status(403).json({ error: 'Owner account cannot be registered via this route. Use login.'});
    }

    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ error:'User already exists' });

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    const user = new User({ name, email, passwordHash: hash, isOwner: false, notify: true });
    await user.save();
    return res.json({ message:'Registered' });
  } catch(err) {
    console.error(err);
    return res.status(500).json({ error:'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error:'Missing fields' });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error:'Invalid credentials' });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(400).json({ error:'Invalid credentials' });

    const token = jwt.sign({ id: user._id, email: user.email, isOwner: user.isOwner }, JWT_SECRET, { expiresIn:'7d' });
    return res.json({ token, email: user.email, isOwner: user.isOwner, name: user.name });
  } catch(err) {
    console.error(err);
    return res.status(500).json({ error:'Server error' });
  }
});

// Subscribe route (save push subscription) — user must be logged in
app.post('/api/subscribe', authMiddleware, async (req, res) => {
  try {
    const sub = req.body.subscription;
    if (!sub) return res.status(400).json({ error:'No subscription' });

    // update user's notify true
    await User.findByIdAndUpdate(req.user.id, { notify: true });

    // upsert subscription
    let existing = await Subscription.findOne({ userId: req.user.id });
    if (existing) {
      existing.subscription = sub;
      await existing.save();
    } else {
      const s = new Subscription({ userId: req.user.id, subscription: sub });
      await s.save();
    }
    return res.json({ message:'Subscribed' });
  } catch(err) {
    console.error(err);
    return res.status(500).json({ error:'Server error' });
  }
});

// Unsubscribe
app.post('/api/unsubscribe', authMiddleware, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.id, { notify: false });
    await Subscription.findOneAndDelete({ userId: req.user.id });
    return res.json({ message:'Unsubscribed' });
  } catch(err) {
    console.error(err);
    return res.status(500).json({ error:'Server error' });
  }
});

// Owner endpoint to send notification to all users who are notify=true and have a subscription
app.post('/api/sendNotification', authMiddleware, async (req, res) => {
  try {
    if (!req.user.isOwner) return res.status(403).json({ error:'Only owner can send notifications' });

    const { title, message } = req.body;
    if (!title || !message) return res.status(400).json({ error:'Missing title or message' });

    // find users with notify=true
    const users = await User.find({ notify: true });
    // collect subscriptions for these users
    const subs = await Subscription.find({ userId: { $in: users.map(u=>u._id) } });
    if (!subs.length) return res.json({ message:'No subscribers to send to' });

    const payload = JSON.stringify({ title, message, url: '/' });

    // send to each
    const results = [];
    let successCount = 0;
    let errorCount = 0;
    for (let s of subs) {
      try {
        await webpush.sendNotification(s.subscription, payload);
        results.push({ userId: s.userId, status:'ok' });
        successCount++;
      } catch(err) {
        console.error('Push error for', s.userId, err);
        results.push({ userId: s.userId, status:'error', error: err.message });
        errorCount++;
        // delete invalid subscriptions (e.g., expired)
        if (err.statusCode === 410 || err.statusCode === 404) {
          await Subscription.findOneAndDelete({ userId: s.userId });
        }
      }
    }
    return res.json({ message:'Notifications sent', success: successCount, errors: errorCount, results });
  } catch(err) {
    console.error(err);
    return res.status(500).json({ error:'Server error' });
  }
});

// New: Get all users list (for owner only) - shows registered users and their notify status
app.get('/api/users', authMiddleware, async (req, res) => {
  if (!req.user.isOwner) return res.status(403).json({ error:'Only owner can view users' });
  try {
    const users = await User.find({}, { _id:0, name:1, email:1, notify:1, isOwner:1 });
    return res.json({ users });
  } catch(err) {
    console.error(err);
    return res.status(500).json({ error:'Server error' });
  }
});

// Get VAPID public key (frontend needs it)
app.get('/api/vapidPublicKey', (req, res) => {
  res.json({ publicKey: VAPID_PUBLIC_KEY });
});

// simple route to check auth
app.get('/api/me', authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ error:'No user' });
  res.json({ email: user.email, name: user.name, isOwner: user.isOwner, notify: user.notify });
});

// serve index.html and sw.js automatically from root (express.static above)
app.listen(PORT, ()=> {
  console.log(`Server running on http://localhost:${PORT}`);
});
