import axios from 'axios';
import jwt_decode from 'jwt-decode';

let { hostname, port } = window.location;

if (process.env.NODE_ENV !== 'production') {
  port = 9090;
  axios.defaults.withCredentials = true;
}

axios.defaults.baseURL = `https://${hostname}:${port}`;

// shared access token for all APIs
let accessToken = null;
let tokenClaims = {};

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
   * Gain an access token.
   * @returns {Promise<null>}
   */
  access() {
    // If an access token already exists, do nothing.
    if (accessToken) {
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
      headers: {
        Authorization: `Bearer ${accessToken}`,
      }
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
      headers: {
        Authorization: `Bearer ${accessToken}`,
      }
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
    return axios({
      method: 'post',
      url: `/api/auth/logout`,
    }).then(() => {
      accessToken = '';
      tokenClaims = {};
      return null;
    });
  }
}
