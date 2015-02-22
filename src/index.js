/* Passport */

"use strict";

var _Q = require('q');
var NoPg = require('nor-nopg');
var Flags = require('nor-flags');
var is = require('nor-is');
var debug = require('nor-debug');
var copy = require('nor-data').copy;
var FUNCTION = require('nor-function');
var ARRAY = require('nor-array');
var passport = require('passport');
var plugins_local = require('./plugins/local');

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

	debug.assert(opts.documents).ignore(undefined).is('object');
	var documents = copy(opts.documents) || null;

	var types = opts.types || {};
	var User = types.User || 'User';
	var Group = types.Group || 'Group';

	if(!is.string(User)) {
		debug.assert(User).is('object').instanceOf(NoPg.Type);
	}

	if(!is.string(Group)) {
		debug.assert(Group).is('object').instanceOf(NoPg.Type);
	}

	debug.assert(opts.user_view).ignore(undefined).is('object');

	opts.userFields = opts.userFields || ['$id', '$type', '$created', 'name', 'email', 'groups', 'flags'];
	debug.assert(opts.userFields).is('array');

	passport.use( plugins_local({"pg":opts.pg, "User": User, "usernameField": "email"}));

	/** Serialize NoPg user object */
	passport.serializeUser(function(user, done) {
		debug.assert(user).is('object');
		debug.assert(done).is('function');
		done(null, user.$id);
	});

	/** Deserialize NoPg user object */
	passport.deserializeUser(function(req, id, done) {

		debug.assert(req).is('object');
		debug.assert(id).is('uuid');
		debug.assert(done).is('function');

		var _db, user;

		var traits = {};
		if(documents) {
			traits.documents = documents;
		}
		traits.fields = opts.userFields;

		NoPg.start(opts.pg).then(function(db) {
			_db = db;
			return db;
		}).searchSingle(User)({'$id':id}, traits).then(function(db) {
			user = NoPg.strip( db.fetch() ).unset('$content').get();

			// The public flag is special and should not be set false in the user record
			if(user.flags && (user.flags['public'] !== undefined)) {
				delete user.flags['public'];
			}

			// Make sure user.flags is correct
			debug.assert(user.flags).is('object');
			ARRAY(Object.keys(user.flags)).forEach(function(key) {
				debug.assert(user.flags[key]).is('boolean');
			});

			user.orig = copy(user);

			//debug.log('user.groups = ', user.groups);

			if(!opts.user_view) {
				return db;
			}

			//debug.log('user.$documents = ', user.$documents);

			return _Q.when(opts.user_view.element({
				"user": user,
				"flags": user.flags,
				"session": req.session,
				"url": req.url
			}, {})(user)).then(function(body) {
				user = body;
				//debug.log('user.$documents = ', user.$documents);
				return db;
			});

		}).then(function(db) {

			if(is.array(user.groups) && (user.groups.length >= 1)) {
				var where = ['OR'].concat( ARRAY(user.groups).map(function(uuid) { return {'$id':uuid}; }).valueOf() );
				return db.search(Group)(where).then(function(db) {
					user.groups = ARRAY( db.fetch() ).map(function(g) {
						return NoPg.strip( g ).unset('$content').unset('$events').get();
					}).valueOf();
					//debug.log('user.groups = ', user.groups);
					return db;
				});
			} else {
				user.groups = [];
				//debug.log('user.groups = ', user.groups);
				return db;
			}
		}).commit().then(function(/*db*/) {

			//debug.log('user.groups = ', user.groups);

			var flags = new Flags();
			ARRAY(user.groups).forEach(function(g) {

				// The public flag is special and should not be set false in the group record
				if(g.flags && (g.flags['public'] !== undefined)) {
					delete g.flags['public'];
				}

				// Make sure `g.flags` is correct
				debug.assert(g.flags).is('object');
				ARRAY(Object.keys(g.flags)).forEach(function(key) {
					debug.assert(g.flags[key]).is('boolean');
				});

				// Merge flags
				flags = flags.merge(g.flags);
			});

			user.flags = flags.merge(user.flags);
			//debug.log('user = ', user);

			// Make sure `user.flags` is still correct
			debug.assert(user.flags).is('object');
			ARRAY(Object.keys(user.flags)).forEach(function(key) {
				debug.assert(user.flags[key]).is('boolean');
			});

			//debug.log('user.flags = ', user.flags);

			done(null, user);
		}).fail(function(err) {
			done(err);
		}).done();
	});

	return mod;
};

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
			ARRAY(Object.keys(req.user.flags)).forEach(function(flag) {
				flags[flag] = is.true(req.user.flags[flag]);
			});
		}

		// Make sure `req.flags` is valid
		debug.assert(req.flags).is('object');
		ARRAY(Object.keys(req.flags)).forEach(function(f) {
			debug.assert(req.flags[f]).is('boolean');
		});

		next();
	};
};

/* Wrappers */
mod.authenticate = FUNCTION(passport.authenticate).bind(passport);
mod.initialize = FUNCTION(passport.initialize).bind(passport);
mod.session = FUNCTION(passport.session).bind(passport);

/* EOF */
