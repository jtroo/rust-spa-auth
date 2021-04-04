import axios from 'axios';
import jwt_decode from 'jwt-decode';
import router from '@/router';

let { hostname, port } = window.location;

// shared access token for all APIs
let accessToken = null;
let tokenClaims = {};

// change parameters for development since it uses CORS
if (process.env.NODE_ENV !== 'production') {
  port = 9090;
  axios.defaults.withCredentials = true;
}

axios.defaults.baseURL = `https://${hostname}:${port}`;

/**
 * Request an access token and stores it in the file variable `accessToken`.
 *
 * @param {bool} force - Set true if a brand new access token should be
 *   requested rather than using the currently saved one.
 * @returns {Promise<null>}
 */
function getAccessToken(force) {
  // If an access token already exists, do nothing.
  if (accessToken && !force) {
    return new Promise((resolve) => resolve(null));
  }

  return axios({
    method: 'get',
    url: `/api/auth/access`,
  }).then((result) => {
    accessToken = result.data;
    tokenClaims = jwt_decode(result.data) || {};
    return null;
  });
}

/**
 * Log out of the system
 * @returns {Promise<null>}
 */
function doLogout() {
  return axios({
    method: 'post',
    url: `/api/auth/logout`,
  }).then(() => {
    accessToken = '';
    tokenClaims = {};
    router.push('/login').catch((e) => {
      if (e.name != 'NavigationDuplicated') {
        throw e;
      }
    });
    return null;
  });
}

axios.interceptors.request.use(
  (config) => {
    if (!config.url.startsWith('/api/auth/')) {
      // Add authorization header for non-auth related APIs
      config.headers.authorization = `Bearer ${accessToken}`;
    }
    return config;
  },
  null,
);

axios.interceptors.response.use(
  null,
  async (e) => {
    // Rethrow any non-authorization errors
    if (!e.response || e.response.status !== 403) {
      throw e;
    }

    const { config } = e;

    // If the original request was related to authorization already, logout and exit early.
    if (config.url.startsWith('/api/auth/')) {
      await doLogout();
      throw e;
    }

    // Get the new access token
    await getAccessToken(true);

    // Resend the original request. Wrap in try/catch so that it only tries
    // once and does not keep repeating.
    return await axios.request(config);
  },
  { synchronous: true },
);

export default {
  /**
   * Attempt login.
   * @returns {Promise<null>}
   */
  login(email, pw) {
    return axios({
      method: 'post',
      url: `/api/login`,
      data: { email, pw },
    }).then(this.access);
  },

  /**
   * Request API access.
   * @returns {Promise<null>}
   */
  access() {
    return getAccessToken();
  },

  /**
   * Get the error message
   * @param {Object} e - Error response from an API.
   * @returns {string}
   */
  getErrorMsg(e) {
    // e.response.data.msg is for custom rejections
    // e.response.data is for default Warp rejections
    // e.message is the default standard error message for the error code
    return e.response && e.response.data.msg || e.response.data || e.message;
  },

  /**
   * Call the user API.
   * @returns {Promise<String>}
   */
  callUser() {
    return axios({
      method: 'post',
      url: `/api/user`,
    }).then((resp) => resp.data);
  },

  /**
   * Call the user API
   * @returns {Promise<String>}
   */
  callAdmin() {
    return axios({
      method: 'post',
      url: `/api/admin`,
    }).then((resp) => resp.data);
  },

  /**
   * Get the claims.
   * @returns {Promise<Object>}
   */
  claims() {
    if (accessToken) {
      return new Promise((resolve) => resolve(tokenClaims));
    }
    return this.access().then(() => tokenClaims);
  },

  /**
   * Log out.
   * @returns {Promise<null>}
   */
  logout() {
    doLogout();
  }
}
