/**
 * Module dependencies.
 */
var util = require('util')
  , OAuthStrategy = require('passport-oauth').OAuthStrategy;


/**
 * `Strategy` constructor.
 *
 * The Twitter authentication strategy authenticates requests by delegating to
 * Twitter using the OAuth protocol.
 *
 * Applications must supply a `verify` callback which accepts a `token`,
 * `tokenSecret` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `consumerKey`     identifies client to Twitter
 *   - `consumerSecret`  secret used to establish ownership of the consumer key
 *   - `callbackURL`     URL to which Twitter will redirect the user after obtaining authorization
 *
 * Examples:
 *
 *     passport.use(new TwitterStrategy({
 *         consumerKey: '123-456-789',
 *         consumerSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/twitter/callback'
 *       },
 *       function(token, tokenSecret, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.requestTokenURL = options.requestTokenURL || 'https://connect.freedomworks.org/oauth/request_token';
  options.accessTokenURL = options.accessTokenURL || 'https://connect.freedomworks.org/oauth/access_token';
  options.userAuthorizationURL = options.userAuthorizationURL || 'http://connect.freedomworks.org/oauth/authorize';
  options.sessionKey = options.sessionKey || 'oauth:freedomworks';

  OAuthStrategy.call(this, options, verify);
  this.name = 'freedomworks';
}

/**
 * Inherit from `OAuthStrategy`.
 */
util.inherits(Strategy, OAuthStrategy);

/**
 * Retrieve user profile from Twitter.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `id`        (equivalent to `user_id`)
 *   - `username`  (equivalent to `screen_name`)
 *
 * Note that because Twitter supplies basic profile information in query
 * parameters when redirecting back to the application, loading of Twitter
 * profiles *does not* result in an additional HTTP request, when the
 * `skipExtendedUserProfile` is enabled.
 *
 * @param {String} token
 * @param {String} tokenSecret
 * @param {Object} params
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(token, tokenSecret, params, done) {
  this._oauth.get('https://connect.freedomworks.org/api/me', token, tokenSecret, function (err, body, res) {
    if (err) { return done(err); }

    try {
      var json = JSON.parse(body);

      var profile = { provider: 'freedomworks' };
      profile.id = json.account.uid;
      profile.username = json.account.name;
      profile.displayName = json.account.first ? json.account.first + ' ' + json.account.last : json.account.name;
      profile.name = {
        familyName: json.account.last,
        givenName: json.account.first
      }
      profile.emails = [{value: json.account.mail, type: 'main'}];

      profile._raw = body;
      profile._json = json.account;

      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
}

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
