var mongoose = require('mongoose'),
  crypto = require('crypto'),
  Schema = mongoose.Schema;

var UserSchema = new Schema({
  firstName: String,
  lastName: String,
  email: {
    type: String,
    index: true,
    match: [/.+\@.+\..+/, 'Please create a valid e-mail address.']
  },
  username: {
    type: String,
    trim: true, 
    unique: true,
    required: 'A username is required.'
  },
  password: {
    type: String,
    validate: [
      function(password) {
        return password && password.length >= 6;
      },
      'Password must be greater than or equal to six characters.'
    ]
  },
  // salt: hashes one's password
  salt: {
    type: String
  },
  // provider: strategy to register user
  provider: {
    type: String,
    required: 'Provider is required.'
  },
  providerId: String,
  // providerData: store user object retrieved from OAuth
  providerData: {},
  created: {
    type: Date,
    default: Date.now
  },
  // created: {
  //   type: Date,
  //   default: Date.now
  // },
  website: {
    type: String,
    set: function (url) {
      if (!url) {
        return url;
      } else {
        if (url.indexOf('http://') !== 0 && url.indexOf('https://') !== 0) {
          url = 'http://' + url;
        }
        return url;
      }
    }
  }
});

UserSchema.virtual('fullName').get(function() {
  return this.firstName + ' ' + this.lastName;
}).set(function (fullName) {
  var splitName = fullName.split(' ');
  this.firstName = splitName[0] || '';
  this.lastName = splitName[1] || '';
});

// Handles hashing of users' passwords
UserSchema.pre('save', function(next) {
  if (this.password) {
    this.salt = new Buffer(crypto.randomBytes(16).toString('base64'), 'base64');
    this.password = this.hashPassword(this.password);
  }

  next();
});

UserSchema.methods.hashPassword = function(password) {
  return crypto.pbkdf2Sync(password, this.salt, 10000, 64).toString('base64');
};

UserSchema.methods.authenticate = function(password) {
  return this.password === this.hashPassword(password);
}; // Creates custom instance method 

UserSchema.statics.findUniqueUsername = function(username, suffix, callback) {
  var _this = this;
  var possibleUsername = username + (suffix || '');

  _this.findOne({
    username: possibleUsername
  }, function(err, user) {
    if (!err) {
      if (!user) {
        callback(possibleUsername);
      } else {
        return _this.findUniqueUsername(username, (suffix || 0) + 1, callback);
      }
    } else {
      callback(null);
    }
  });
};

UserSchema.set('toJSON', { 
  getters: true, 
  virtuals: true 
});

mongoose.model('User', UserSchema);
