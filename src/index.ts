import { Request } from 'express';
import https from 'https';
import passport from 'passport-strategy';
import { AuthenticateOptions } from 'passport';
import qs from 'query-string';
import Url from 'url-parse';
import { convertableToString, parseString as parseXmlString } from 'xml2js';
import processors from 'xml2js/lib/processors';

/**
 * CAS 2 options when constructing the {@link Cas2Strategy}.
 */
interface StrategyOptions extends AuthenticateOptions {
  /**
   * CAS server base URL
   * @example "https://www.example.com"
   * */
  ssoBaseUrl: string;

  /**
   * CAS server login URL
   * @example "https://www.example.com/cas/login"
   */
  ssoLoginUrl: string;

  /**
   * CAS validation endpoint. This will be appended to {@link ssoBaseUrl}
   * @example "/cas/serviceValidate"
   */
  validateEndpoint: string;

  /**
   * Application URL that the browser is redirected to after successful authentication.
   * @example "https://myapp.com/login"
   */
  appServiceUrl: string;
}

/**
 * Function signature that will be called after the CAS server confirms a successful authentication.
 * 
 * @param userAttribs - The attributes sent by the CAS server, converted from XML to an object.
 * More specifically, this is the "authenticationSuccess" element and its children.
 * 
 * @param done - Function that you can call after 
 */
type VerifyCallback = (userAttribs: object, done: Function) => void

/** Passport strategy for CAS 2 authentication */
export class Cas2Strategy extends passport.Strategy implements StrategyOptions {
  name: string = 'cas2';

  verifyCallback: VerifyCallback;

  ssoBaseUrl: string;
  ssoLoginUrl: string;
  validateEndpoint: string;
  appServiceUrl: string;

  constructor(options: StrategyOptions, verifyCallback: VerifyCallback) {
    super();
    this.verifyCallback = verifyCallback;
    this.ssoBaseUrl = options.ssoBaseUrl;
    this.ssoLoginUrl = options.ssoLoginUrl;
    this.validateEndpoint = options.validateEndpoint;
    this.appServiceUrl = options.appServiceUrl;
  }

  /**
   * Parse and validate the XML response from the CAS server
   */
  private validate(req: Request, data: convertableToString, verified: (err: Error | null, user?: unknown, info?: { message: string; }) => void) {
    // Set XML parse options
    const xmlParseOpts = {
      'trim': true,
      'normalize': true,
      'explicitArray': false,
      // Set all property names to lower case
      'tagNameProcessors': [processors.normalize, processors.stripPrefix]
    };

    try {
      parseXmlString(data, xmlParseOpts, (error, result) => {

        if (error) {
          console.error(error);
          return verified(error);
        }

        // Check if authenticationsuccess element has a value
        const authSuccess = result.serviceresponse && result.serviceresponse.authenticationsuccess ? true : false;
        // Check if authenticationfailure element has a value
        const authFailure = result.serviceresponse && result.serviceresponse.authenticationfailure ? true : false;

        // Authentication success
        if (authSuccess && !authFailure) {
          // Extract user attributes (MODIFIED)
          //user = result.serviceresponse.authenticationsuccess.attributes;
          const userAttribs: object = result.serviceresponse.authenticationsuccess;

          // Verify callback
          return this.verifyCallback(userAttribs, verified);

        }


        // Authentication failed
        else if (authFailure) {
          // Extract auth failure value
          let authError = result.serviceresponse.authenticationfailure;

          // Extract error code
          const errorCode = result.serviceresponse.authenticationfailure['$'].code;

          // Check error code
          if (errorCode === 'INVALID_TICKET') {
            return verified(null, false, { message: `Authentication timed out` });
          }

          return verified(null, false, { message: `Authentication failed` });

        }

        return verified(new Error());

      });
    } catch (err) {
      console.error(err);
      return verified(err as Error);
    }

  };

  /**
   * CAS 2.0
   *
   * @param {Object} req request object
   * @param {Object} options options passed in when calling authenticate
   */
  
  authenticate(req: Request, options: any = {}) {
    /**
     * Check if a ticket has been sent back from the CAS server,
     * if the user has not logged in yet, this parmater will be empty
     * After the user logs in, the CAS server will redirect back
     * to the application service url automatically,
     * providing the ticket in the request query `ticket` parameter
     */
    let ticket = req.query['ticket'];

    // Generate service url
    let serviceUrl = new Url(this.appServiceUrl, true);

    // Add session ID as a query parameter if it exists
    if (req.query['sessionId']) {
      serviceUrl.query.sessionId = req.query['sessionId'].toString();
    }

    // If no ticket is in the query parameter
    if (!ticket) {
      // Create the SSO login URL
      let loginUrl = new Url(this.ssoLoginUrl, true);
      // Add service url as a query parameter
      loginUrl.query.service = serviceUrl.toString();
      // Redirect to the CAS login URL to get the ticket
      return this.redirect(loginUrl.toString());
    }

    // Store a reference to this context
    const self = this;

    // Wrapper for verification callback
    const verified = (err: Error | null, user?: unknown, info?: { message: string; }) => {
      if (err) { return self.error(err); }
      if (!user) { return self.fail(info, 401); }
      self.success(user, info);
    };

    // Create the validation query string with ticket and service request parameters
    const validateQueryString = qs.stringify({
      service: serviceUrl,
      ticket: ticket,
    });

    // Generate the URL to send the service validation request
    const serviceValidateUrl = `${this.ssoBaseUrl}${this.validateEndpoint}?${validateQueryString}`;

    try {
      // Send a GET request to the service validation URL
      const request = https.get(serviceValidateUrl, (response) => {
        console.log(`Passport cas2 service validation response status code: ${response.statusCode}`);
        /**
         * Log full response from the CAS server
         * Warning: CONFIDENTIAL information may be printed to the logs
         * Do not enable this option in production
         */
        if (process.env.CAS2_LOG_RESPONSE) {
          console.log(response);
        }

        // Set encoding
        response.setEncoding('utf8');

        // Initialize variable to store data
        let rawData = '';

        // Capture each chunk of data in the response
        response.on('data', (chunk) => {
          // Append latest chunk to raw data
          rawData += chunk;
        });

        // All data has been received in the response
        response.on('end', () => {
          console.log(rawData);
          // Parse and validate the XML response
          return self.validate(req, rawData, verified);
        });

      });

      request.on('error', (err: Error) => {
        return this.error(err);
      });

      request.end();

    } catch (err) {
      return this.error(err as Error);
    }

  }
}