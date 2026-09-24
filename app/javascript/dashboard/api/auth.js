/* global axios */

import Cookies from 'js-cookie';
import endPoints from './endPoints';
import {
  clearCookiesOnLogout,
  deleteIndexedDBOnLogout,
} from '../store/utils/api';
import { isSSOMode } from 'shared/helpers/ssoMode';

export default {
  validityCheck() {
    const urlData = endPoints('validityCheck');
    return axios.get(urlData.url);
  },
  logout() {
    // audit row 14 — under SSO, per-app logout is NAVIGATION-ONLY.
    //
    // DELETE /auth/sign_out is skipped only in SSO mode: it cleared the Rails-side
    // token, but the next request would immediately re-establish a session from
    // X-Auth-Request-Email, so the user-visible result was identical while the
    // request added a failure mode. Real sign-out is the portal's "logout all",
    // which clears the shared _oauth2_proxy cookie.
    //
    // Stock Chatwoot still calls it: without SSO the devise token is the whole
    // session, and skipping the request would leave it valid for its full lifespan
    // after the user believes they have logged out.
    //
    // The portal URL is deployer-supplied and already handled by
    // clearCookiesOnLogout(), which reads globalConfig.LOGOUT_REDIRECT_LINK and
    // navigates (store/utils/api.js:91-93). Never derive the host by rewriting the
    // hostname, and never point at /oauth2/sign_out.
    if (isSSOMode()) {
      deleteIndexedDBOnLogout();
      clearCookiesOnLogout(window.globalConfig?.MPASS_PORTAL_URL);
      return Promise.resolve();
    }

    const urlData = endPoints('logout');
    const fetchPromise = new Promise((resolve, reject) => {
      axios
        .delete(urlData.url)
        .then(response => {
          deleteIndexedDBOnLogout();
          clearCookiesOnLogout();
          resolve(response);
        })
        .catch(error => {
          reject(error);
        });
    });
    return fetchPromise;
  },
  hasAuthCookie() {
    return !!Cookies.get('cw_d_session_info');
  },
  getAuthData() {
    if (this.hasAuthCookie()) {
      const savedAuthInfo = Cookies.get('cw_d_session_info');
      return JSON.parse(savedAuthInfo || '{}');
    }
    return false;
  },
  profileUpdate({ displayName, avatar, ...profileAttributes }) {
    const formData = new FormData();
    Object.keys(profileAttributes).forEach(key => {
      const hasValue = profileAttributes[key] === undefined;
      if (!hasValue) {
        formData.append(`profile[${key}]`, profileAttributes[key]);
      }
    });
    formData.append('profile[display_name]', displayName || '');
    if (avatar) {
      formData.append('profile[avatar]', avatar);
    }
    return axios.put(endPoints('profileUpdate').url, formData);
  },

  profilePasswordUpdate({ currentPassword, password, passwordConfirmation }) {
    return axios.put(endPoints('profileUpdate').url, {
      profile: {
        current_password: currentPassword,
        password,
        password_confirmation: passwordConfirmation,
      },
    });
  },

  updateUISettings({ uiSettings }) {
    return axios.put(endPoints('profileUpdate').url, {
      profile: { ui_settings: uiSettings },
    });
  },

  updateAvailability(availabilityData) {
    return axios.post(endPoints('availabilityUpdate').url, {
      profile: { ...availabilityData },
    });
  },

  updateAutoOffline(accountId, autoOffline = false) {
    return axios.post(endPoints('autoOffline').url, {
      profile: { account_id: accountId, auto_offline: autoOffline },
    });
  },

  deleteAvatar() {
    return axios.delete(endPoints('deleteAvatar').url);
  },

  resetPassword({ email }) {
    const urlData = endPoints('resetPassword');
    return axios.post(urlData.url, { email });
  },

  setActiveAccount({ accountId }) {
    const urlData = endPoints('setActiveAccount');
    return axios.put(urlData.url, {
      profile: {
        account_id: accountId,
      },
    });
  },
  resendConfirmation() {
    const urlData = endPoints('resendConfirmation');
    return axios.post(urlData.url);
  },
  resetAccessToken() {
    const urlData = endPoints('resetAccessToken');
    return axios.post(urlData.url);
  },
  getSessions() {
    return axios.get('/api/v1/profile/sessions');
  },
  revokeSession(id) {
    return axios.delete(`/api/v1/profile/sessions/${id}`);
  },
};
