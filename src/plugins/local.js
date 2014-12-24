/* Local passport strategy */

"use strict";

var is = require('nor-is');
var debug = require('nor-debug');
//var nordata = require('nor-data');
var util = require('util');
var NoPg = require('nor-nopg');
var Strategy = require('passport-local').Strategy;
var crypt = require('crypt3');

module.exports = function(opts) {
	opts = opts || {};

	//debug.log('opts = ', opts);

	var pg_config = opts.pg;
	if(!pg_config) { throw new TypeError("opts.pg invalid: " + util.inspect(pg_config) ); }

	//debug.log('pg_config = ', pg_config);

	var User = opts.User || "User";
	var usernameField = opts.usernameField || 'username';
	var passwordField = opts.passwordField || 'password';

	if(!is.string(User)) {
		debug.assert(User).is('object').instanceOf(NoPg.Type);
	}

	debug.assert(usernameField).is('string');
	debug.assert(passwordField).is('string');

	//debug.log('usernameField = ', usernameField);
	//debug.log('passwordField = ', passwordField);

	return new Strategy({usernameField: usernameField, passwordField:passwordField}, function(username, password, done) {

		debug.assert(username).is('string');
		debug.assert(password).is('string');
		debug.assert(done).is('function');

		//debug.log('username = ', username);
		//debug.log('password = ', password);

		var _db;
		var where = {};
		where[usernameField] = username.toLowerCase();

		//debug.log('where = ', where);

		NoPg.start(pg_config).then(function(db) {
			_db = db;
			return db;
		}).search(User)(where).commit().then(function(db) {
			var users = db.fetch();
			//debug.log('users = ', users);
			if(!users) { throw new TypeError("No users received!"); }

			var user = users.shift();
			//debug.log('user = ', user);
			if(!user) {
				return false;
			}

			//debug.log('password = ', password);
			//debug.log('user[passwordField] = ', user[passwordField]);
			if( crypt(password, user[passwordField]) !== user[passwordField] ) {
				return false;
			} else {
				//delete user[passwordField];
				//debug.log('user = ', user);
				user = NoPg.strip(user).unset('$content').unset(passwordField).get();
				return user;
			}

		}).then(function(user) {
			//debug.log('user =', user);
			debug.assert(done).is('function');
			return done(null, user);
		}).fail(function(err) {
			debug.error( ((err && err.stack) || err) );
			debug.assert(done).is('function');
			if(_db) {
				return _db.rollback().fin(function() { done(err); });
			}
			done(err);
		}).done();

	});
};

/* EOF */
