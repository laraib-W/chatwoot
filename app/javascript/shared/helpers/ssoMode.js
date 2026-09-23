// Single definition of the mPass SSO surface shared by both bundles.
//
// AUTH_TYPE is read from window.globalConfig rather than the Vuex globalConfig
// module because the earliest callers (the axios interceptor, the v3 router guard)
// run before the store exists. DashboardController#app_config injects it per
// request, so it is never baked into a build.
export const isSSOMode = () => window.globalConfig?.AUTH_TYPE === 'SSO';

// Set by Api::BaseController#flush_stale_mpass_session, and by nothing else, so the
// SPA can tell a Rule 2 identity flush apart from an ordinary permission 401.
// Lowercase: axios normalises response header names.
export const SSO_FLUSH_HEADER = 'x-mpass-session-flushed';

// The ForwardAuth handoff (config/routes.rb). A full navigation, never a soft route.
export const SSO_HANDOFF_PATH = '/auth/sso/proxy-login';
