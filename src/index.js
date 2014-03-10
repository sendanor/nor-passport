/* Passport */

var NoPg = require('nor-nopg');
var Flags = require('nor-flags');
var is = require('nor-is');
var debug = require('nor-debug');
var copy = require('nor-data').copy;

var passport = require('passport');

var mod = module.exports = {};

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
		}).search(User)({'$id':id}, {'fields':['$id', '$type', '$created', 'email', 'groups', 'sites', 'flags']} ).then(function(db) {
			user = NoPg.strip( db.fetchSingle() ).unset('$content').get();
			user.orig = copy(user);
			if(is.array(user.groups)) {
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
				flags = flags.merge(g.flags);
			});
	
			user.flags = flags.merge(user.flags);
			//debug.log('user = ', user);
	
			done(null, user);
		}).fail(function(err) {
			done(err);
		}).done();
	});

	return mod;
}

/* Express auth helpers */
mod.setupHelpers = function() {
	return function(req, res, next){
		res.locals.isAuthenticated = req.isAuthenticated();
		res.locals.user = res.locals.isAuthenticated ? req.user : undefined;
		res.locals.profile = res.locals.user;

		/* Setup `req.flags`, the user access flags. Even users that aren't connected will have some access flags. */
		var flags = {
			'public': true
		};

		req.flags = flags;
		res.locals.flags = flags;

		if(req.isAuthenticated() && is.obj(req.user)) {
			flags.authenticated = true;
		}

		if(flags.authenticated && is.obj(req.user.flags) ) {
			Object.keys(req.user.flags).forEach(function(flag) {
				flags[flag] = is.true(req.user.flags[flag]);
			});
		}

		next();
	};
};

/* Wrappers */
mod.authenticate = passport.authenticate.bind(passport);
mod.initialize = passport.initialize.bind(passport);
mod.session = passport.session.bind(passport);

/* EOF */
