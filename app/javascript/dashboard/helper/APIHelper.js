import Auth from '../api/auth';
import { clearBrowserSessionCookies } from '../store/utils/api';

const parseErrorCode = error => Promise.reject(error);

// audit row 20 — makes Rule 2's XHR flush observable.
//
// Auth headers are bound ONCE at instance creation (below), read from the cookie
// at that moment. After the server evicts the token, this instance keeps replaying
// the dead credential until a full page load — so this must hard-navigate rather
// than soft-route, and must clear the cookie first or the login route's guard sees
// a cookie matching no live token.
const handleUnauthorized = error => {
  if (error?.response?.status === 401 && Auth.hasAuthCookie()) {
    // Cookie-only clear, not clearCookiesOnLogout() — that one navigates to the
    // portal (LOGOUT_REDIRECT_LINK). A Rule 2 flush is not a logout: the user is
    // still authenticated upstream, so send them to the login route to re-enter
    // the handoff as the incoming identity.
    clearBrowserSessionCookies();
    window.location.href = '/app/login';
  }
  return Promise.reject(error);
};

export default axios => {
  const { apiHost = '' } = window.chatwootConfig || {};
  const wootApi = axios.create({ baseURL: `${apiHost}/` });
  // Add Auth Headers to requests if logged in
  if (Auth.hasAuthCookie()) {
    const {
      'access-token': accessToken,
      'token-type': tokenType,
      client,
      expiry,
      uid,
    } = Auth.getAuthData();
    Object.assign(wootApi.defaults.headers.common, {
      'access-token': accessToken,
      'token-type': tokenType,
      client,
      expiry,
      uid,
    });
  }
  // Response parsing interceptor
  wootApi.interceptors.response.use(
    response => response,
    error => handleUnauthorized(error).catch(parseErrorCode)
  );
  return wootApi;
};
