/* Local passport strategy */

"use strict";

var is = require('nor-is');
var debug = require('nor-debug');
//var nordata = require('nor-data');
var util = require('util');
var NoPg = require('nor-nopg');
var Strategy = require('passport-local').Strategy;
var crypt = require('crypt3/q');

module.exports = function(opts) {
	opts = opts || {};

	var pg_config = opts.pg;
	if(!pg_config) { throw new TypeError("opts.pg invalid: " + util.inspect(pg_config) ); }

	var User = opts.User || "User";
	var usernameField = opts.usernameField || 'username';
	var passwordField = opts.passwordField || 'password';

	if(!is.string(User)) {
		debug.assert(User).is('object').instanceOf(NoPg.Type);
	}

	debug.assert(usernameField).is('string');
	debug.assert(passwordField).is('string');

	return new Strategy({usernameField: usernameField, passwordField:passwordField}, function(username, password, done) {

		debug.assert(username).is('string');
		debug.assert(password).is('string');
		debug.assert(done).is('function');

		//debug.log('username = ', username);
		//debug.log('password = ', password);

		var where = {};
		where[usernameField] = username.toLowerCase();

		NoPg.transaction(pg_config, function(db) {
			return db.searchSingle(User)(where).then(function(db) {
				var user = db.fetch();
				if(!user) { return false; }
				if(!user.hasOwnProperty(passwordField)) { return false; }

				return crypt(password, user[passwordField]).then(function(value) {
					if( value !== user[passwordField] ) {
						return false;
					} else {
						user = NoPg.strip(user).unset('$content').unset(passwordField).get();
						return user;
					}
				});
			});
		}).then(function(user) {
			debug.assert(done).is('function');
			return done(null, user);
		}).fail(function(err) {
			debug.error(err);
			debug.assert(done).is('function');
			done(err);
		}).done();

	});
};

/* EOF */
