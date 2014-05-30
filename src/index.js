/* Passport */

var NoPg = require('nor-nopg');
var Flags = require('nor-flags');
var is = require('nor-is');
var debug = require('nor-debug');
var copy = require('nor-data').copy;

var passport = require('passport');

var mod = module.exports = {};

mod.internal = passport;

/* */
mod.setup = function(opts) {
	opts = opts || {};

	//debug.log('opts = ', opts);
	
	// FIXME: check opts.pg
	// FIXME: check opts.types
	// FIXME: check opts.types.User
	// FIXME: check opts.types.Group
	
	var types = opts.types || {};
	var User = types.User || 'User';
	var Group = types.Group || 'Group';

	if(!is.string(User)) {
		debug.assert(User).is('object').instanceOf(NoPg.Type);
	}

	if(!is.string(Group)) {
		debug.assert(Group).is('object').instanceOf(NoPg.Type);
	}

	opts.userFields = opts.userFields || ['$id', '$type', '$created', 'name', 'email', 'groups', 'flags'];
	debug.assert(opts.userFields).is('array');
	
	passport.use(require('./plugins/local')({"pg":opts.pg, "User": User, "usernameField": "email"}));
	
	/** Serialize NoPg user object */	
	passport.serializeUser(function(user, done) {
		done(null, user.$id);
	});
	
	/** Deserialize NoPg user object */
	passport.deserializeUser(function(id, done) {
		var _db, user;
		NoPg.start(opts.pg).then(function(db) {
			_db = db;
			return db;
		}).search(User)({'$id':id}, {'fields':opts.userFields} ).then(function(db) {
			user = NoPg.strip( db.fetchSingle() ).unset('$content').get();

			// The public flag is special and should not be set false in the user record
			if(user.flags && (user.flags['public'] !== undefined)) {
				delete user.flags['public'];
			}

			// Make sure user.flags is correct
			debug.assert(user.flags).is('object');
			Object.keys(user.flags).forEach(function(key) {
				debug.assert(user.flags[key]).is('boolean');
			});
	
			user.orig = copy(user);
			if(is.array(user.groups) && (user.groups.length >= 1)) {
				return db.search(Group)( ['OR'].concat(user.groups.map(function(uuid) { return {'$id':uuid}; })) ).then(function(db) {
					user.groups = db.fetch();
					return db;
				});
			} else {
				user.groups = [];
				return db;
			}
		}).commit().then(function(db) {

			var flags = new Flags();
			user.groups.forEach(function(g) {

				// The public flag is special and should not be set false in the group record
				if(g.flags && (g.flags['public'] !== undefined)) {
					delete g.flags['public'];
				}

				// Make sure `g.flags` is correct
				debug.assert(g.flags).is('object');
				Object.keys(g.flags).forEach(function(key) {
					debug.assert(g.flags[key]).is('boolean');
				});

				// Merge flags
				flags = flags.merge(g.flags);
			});

			user.flags = flags.merge(user.flags);
			//debug.log('user = ', user);

			// Make sure `user.flags` is still correct
			debug.assert(user.flags).is('object');
			Object.keys(user.flags).forEach(function(key) {
				debug.assert(user.flags[key]).is('boolean');
			});

			//debug.log('user.flags = ', user.flags);

			done(null, user);
		}).fail(function(err) {
			done(err);
		}).done();
	});

	return mod;
}

/* Express auth helpers */
mod.setupHelpers = function(opts) {
	opts = opts || {};
	
	if(!is.obj(opts.default_flags)) {
		opts.default_flags = {};
	}

	return function(req, res, next){

		//debug.log('here');

		debug.assert(req).is('object');
		debug.assert(res).is('object');
		debug.assert(next).is('function');

		res.locals.isAuthenticated = req.isAuthenticated();
		res.locals.user = res.locals.isAuthenticated ? req.user : undefined;
		res.locals.profile = res.locals.user;

		/* Setup `req.flags`, the user access flags. Even users that aren't connected will have some access flags. */
		var flags = copy(opts.default_flags);

		req.flags = flags;
		res.locals.flags = flags;

		if(req.isAuthenticated() && is.obj(req.user)) {
			flags.authenticated = true;
		} else {
			flags.authenticated = false;
		}

		if(flags.authenticated && is.obj(req.user.flags) ) {
			Object.keys(req.user.flags).forEach(function(flag) {
				flags[flag] = is.true(req.user.flags[flag]);
			});
		}

		// Make sure `req.flags` is valid
		debug.assert(req.flags).is('object');
		Object.keys(req.flags).forEach(function(f) {
			debug.assert(req.flags[f]).is('boolean');
		});

		next();
	};
};

/* Wrappers */
mod.authenticate = passport.authenticate.bind(passport);
mod.initialize = passport.initialize.bind(passport);
mod.session = passport.session.bind(passport);

/* EOF */
