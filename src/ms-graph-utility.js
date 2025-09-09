/*
 * TODO: refactor to use:
 * const {Client} = require('@microsoft/microsoft-graph-client')
 */
const msalConfig = require('../config/msal.config');
const Msal = require('msal');
// Let fetch = require('node-fetch')

class RESTHandler {
  constructor(logger) {
    this.logger = logger;
    logger.log('Inst. restHandler');
    try {
      this.myMSALObj = new Msal.UserAgentApplication(msalConfig);
    } catch (error) {
      logger.error(error);
    }
    logger.log('Finished Inst. restHandler');
  }

  setStandalone(standalone) {
    this.standalone = standalone;
  }

  makeGetRequest(url, raw = false) {
    return new Promise(resolve => {
      this.getAuthToken().then(() => {
        fetch(url, {
          'headers': {
            'Authorization': `Bearer ${this.accessToken}`,
            'Content-Type': 'application/json'
          }
        }).then(response => {
          if (raw) {
            return response.text();
          }

          return response.json();
        }).then(results => {
          resolve(results);
        }).catch(error => {
          this.logger.error(error);
          throw error;
        });
      }).catch(error => {
        this.logger.error(error);
        throw error;
      });
    });
  }

  getAuthToken() {
    if (this.accessToken) {
      // We already got it
      return new Promise(resolve => {
        resolve();
      });
    }
    // Get login from/for standalone web version
    if (this.myMSALObj.getAccount()) {
      // Account signed in, fetch auth token
      return new Promise(resolve => {
        this.acquireToken(token => {
          this.accessToken = token;
          resolve();
        });
      });
    }

    // Sign in required
    return new Promise(resolve => {
      this.signIn(token => {
        this.accessToken = token;
        resolve();
      });
    });
  }

  signIn(tokenCallback) {
    this.myMSALObj.loginPopup({
      'scopes': msalConfig.graphScopes
    }).then(loginResponse => {
      // Login Success
      this.logger.log(loginResponse);
      this.acquireToken(tokenCallback);
    }).
      catch(error => {
        this.logger.error(error);
      });
  }

  acquireToken(callback) {
    /*
     * Always start with acquireTokenSilent
     * to obtain a token in the signed in user from cache
     */
    this.myMSALObj.acquireTokenSilent({
      'scopes': msalConfig.graphScopes
    }).then(tokenResponse => {
      callback(tokenResponse.accessToken);
    }).catch(error => {
      this.logger.error(error);
      /*
       * Upon acquireTokenSilent failure (due to consent or interaction or login required ONLY)
       * Call acquireTokenPopup(popup window)
       */
      if (this.requiresInteraction(error.errorCode)) {
        this.myMSALObj.acquireTokenPopup({
          'scopes': msalConfig.graphScopes
        }).then(tokenResponse => {
          callback(tokenResponse.accessToken);
        }).
          catch(error => {
            this.logger.error(error);
          });
      }
    });
  }

  requiresInteraction(errorCode) {
    this.logger.log(`errorCode=${errorCode}`);
    if (!errorCode || !errorCode.length) {
      return false;
    }

    return errorCode === 'consent_required' ||
      errorCode === 'interaction_required' ||
      errorCode === 'login_required' ||
      errorCode === 'token_renewal_error';
    // The last condition was added unofficially
  }
}

module.exports = RESTHandler;
