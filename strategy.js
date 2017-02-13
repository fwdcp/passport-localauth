const isFunction = require('lodash/isFunction');
const isNil = require('lodash/isNil');
const Strategy = require('passport-strategy');

class LocalAuthStrategy extends Strategy {
    constructor(verify) {
        super();

        if (!isFunction(verify)) {
            throw new TypeError('LocalAuthStrategy requires a valid verify callback');
        }

        this.name = 'localauth';
        this._verify = verify;
    }

    authenticate(req, options) {
        try {
            this._verify(req, function authenticateCallback(err, user, info) {
                if (err) {
                    this.error(err);
                }
                else if (isNil(user) || user === false) {
                    this.fail(info);
                }
                else {
                    this.success(user);
                }
            }.bind(this));
        }
        catch (err) {
            this.error(err);
        }
    }
}

module.exports = LocalAuthStrategy;
