const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const app = express();
const port = process.env.PORT || 3000;


const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;




app.use(express.static('develop'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());
// Connect to MongoDB
mongoose.connect('', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('Error connecting to MongoDB:', err));



// Session configuration
app.use(session({
  secret: '',
  resave: false,
  saveUninitialized: true
}));

// Passport configuration
app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({
  clientID: '',
  clientSecret: '',
  callbackURL: 'http://localhost:3000/auth/google/callback'
},
  function(accessToken, refreshToken, profile, done) {
    // Here, you can create or find the user in your database
    // and associate the Google profile with the user
    // For simplicity, we'll just return the profile
    return done(null, profile);
  }
));


passport.use(new FacebookStrategy({
  clientID: '',
  clientSecret: '',
  callbackURL: 'http://localhost:3000/auth/facebook/callback',
},
function(accessToken, refreshToken, profile, done) {
  // Here, you can create or find the user in your database
  // and associate the Google profile with the user
  // For simplicity, we'll just return the profile
  return done(null, profile);
}
));


passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

// Routes
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  function(req, res) {
    // Successful authentication, redirect to the index page
    res.sendFile(__dirname + '/page1.html')
  });

  app.use(express.static(__dirname));

app.get('/auth/facebook',
    passport.authenticate('facebook'));
  
  app.get('/auth/facebook/callback',
    passport.authenticate('facebook', { failureRedirect: '/' }),
    function(req, res) {
      res.sendFile(path.join(__dirname, 'page1.html'));
    });



  app.get('/logout', function(req, res) {
    req.logout(function(err) {
      if (err) {
        // Handle error
        console.error('Error logging out:', err);
        return res.status(500).send('Error logging out');
      }
      // Successful logout
      res.redirect('index.html'); // Redirect to the index page (or any other desired page)
    });
  });
  











// Define the Mongoose schemas and models
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

// Middleware
// Authentication middleware
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

// Authorization middleware
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

// Seed predefined roles and permissions
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

// Routes
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




app.post('/login', async (req, res) => {
  try {
    const { email, password, role } = req.body;
    const user = await User.findOne({ email });
    console.log(user);
    if (!user || password !== user.password || user.role !== role) {
      return res.status(401).json({ message: 'Invalid email, password, or role' });
    }
    const token = jwt.sign({ userId: user._id, role: user.role }, 'your_secret_key', { expiresIn: '1h' });
    res.json({ token });
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
