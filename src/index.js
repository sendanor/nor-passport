/* Passport */

var NoPg = require('nor-nopg');
var passport = require('passport');
var Flags = require('nor-flags');
var is = require('nor-is');
var debug = require('nor-debug');
var copy = require('nor-data').copy;

module.exports = function(opts) {
	opts = opts || {};
	
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

	return passport;
}

/* EOF */
