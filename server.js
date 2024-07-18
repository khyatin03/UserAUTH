const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();
const port = process.env.PORT || 3000;

app.use(express.static('develop'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

mongoose.connect('', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('Error connecting to MongoDB:', err));



passport.use(new GoogleStrategy({
  clientID: '',
  clientSecret: '',
  callbackURL: 'http://localhost:3000/auth/google/callback'
},
  function(accessToken, refreshToken, profile, done) {
    return done(null, profile);
  }
));

app.use(session({
  secret: process.env.SESSION_SECRET ||'',
  resave: false,
  saveUninitialized: true
}));



app.use(passport.initialize());
app.use(passport.session());


passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  function(req, res) {
    res.redirect('/page1.html');
  });

// Serve static files from the "public" directory
app.use(express.static(__dirname));

// Serve index.html on the root route
app.get('/index', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

  app.post('/index', async (req, res) => {
    try {
      const { email, password, role } = req.body;
      const user = await User.findOne({ email });
      console.log(user);
      if (!user || !await bcrypt.compare(password, user.password) || user.role !== role) {
        return res.status(401).json({ message: 'Invalid email, password, or role' });
      }
      const token = jwt.sign({ userId: user._id, role: user.role }, 'your_secret_key', { expiresIn: '1h' });
      res.json({ token });
    } catch (err) {
      res.status(400).json({ message: err.message });
    }
  });




app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error('Error logging out:', err);
      return res.status(500).send('Error logging out');
    }
    res.clearCookie('token');
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).send('Error logging out');
      }
      res.redirect('/');
    });
  });
});







const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, required: true, default: 'user' }
});

const roleSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  permissions: { type: [String], required: true }
});

const serviceSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  price: { type: Number, required: true }
});

const User = mongoose.model('User', userSchema);
const Role = mongoose.model('Role', roleSchema);
const Service = mongoose.model('Service', serviceSchema);

const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    const decoded = jwt.verify(token, 'your_secret_key');
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

const authorize = (permissions = []) => {
  return async (req, res, next) => {
    try {
      const role = await Role.findOne({ name: req.user.role });
      if (!role || !permissions.every(p => role.permissions.includes(p))) {
        return res.status(403).json({ message: 'Forbidden' });
      }
      next();
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
  };
};

const seedRoles = async () => {
  try {
    const adminRole = await Role.findOne({ name: 'admin' });
    const userRole = await Role.findOne({ name: 'user' });

    if (!adminRole) {
      const newAdminRole = new Role({
        name: 'admin',
        permissions: ['create:service', 'read:service', 'update:service', 'delete:service']
      });
      await newAdminRole.save();
      console.log('Admin role created');
    }

    if (!userRole) {
      const newUserRole = new Role({
        name: 'user',
        permissions: ['read:service']
      });
      await newUserRole.save();
      console.log('User role created');
    }
  } catch (err) {
    console.error('Error seeding roles:', err);
  }
};

app.post('/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword, role });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});



app.get('/profile', authenticate, (req, res) => {
  res.json({
    name: req.user.name,
    email: req.user.email,
    role: req.user.role
  });
});

app.get('/services', authenticate, authorize(['read:service']), async (req, res) => {
  try {
    const services = await Service.find();
    res.json(services);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/services', authenticate, authorize(['create:service']), async (req, res) => {
  try {
    const { name, description, price } = req.body;
    const service = new Service({ name, description, price });
    await service.save();
    res.status(201).json({ message: 'Service created successfully' });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
