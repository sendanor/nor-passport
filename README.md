nor-passportjs
==============

PassportJS helpers

### Usage

```
// Passport
var passport = require('nor-passport');
passport.setup({  
    'pg': config.pg,
    'types': {
       'User': types.User,
       'Group': types.Group
    }
});

// ...

app.use(passport.initialize());
app.use(passport.session());

```

Commercial Support
------------------

You can buy commercial support from [Sendanor](http://sendanor.com/software).
