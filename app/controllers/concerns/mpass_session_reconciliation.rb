# frozen_string_literal: true

# Rule 2 — session-identity reconciliation (audit row 20).
#
# When the browser holds a session for user A but oauth2-proxy asserts user B, the
# stale session MUST be flushed before anything else happens. Chatwoot's credential
# is client-held (a devise_token_auth triple the SPA persists into the JS-readable
# cw_d_session_info cookie), so the server cannot clear it directly — hence two
# paths, both defined here so "mismatch" has exactly one definition:
#
#   Path A (DashboardController) — document requests, resolved by redirecting
#     through the handoff, which re-mints for B. RouteHelper.js:23-27 already clears
#     the previous cookie whenever the login route carries email + sso_auth_token.
#   Path B (Api::BaseController) — XHR, which cannot be redirected. Evict the
#     request's token and answer 401; the SPA's 401 handler hard-navigates.
#
# Header ABSENCE is never a mismatch. Internal traffic (Sidekiq, health probes,
# direct container hits) carries no header and must not be logged out.
module MpassSessionReconciliation
  extend ActiveSupport::Concern

  # Mirrored by SSO_FLUSH_HEADER in shared/helpers/ssoMode.js.
  SSO_FLUSH_HEADER = 'X-Mpass-Session-Flushed'

  private

  def mpass_identity_mismatch?
    return false unless ENV.fetch('AUTH_TYPE', nil) == 'SSO'

    incoming = Mpass::ProxyIdentity.email(request)
    return false if incoming.blank?

    current = mpass_session_email
    return false if current.blank?

    current != incoming
  end

  # Resolving "who does the browser think it is" differs by path, because Chatwoot's
  # credential is client-held:
  #
  #   XHR       — the SPA replays the devise_token_auth headers, so SetUserByToken
  #               has already populated current_user.
  #   Document  — a browser navigation sends NO auth headers, only the
  #               cw_d_session_info cookie. DashboardController descends from
  #               ActionController::Base and never includes SetUserByToken, so
  #               current_user does not exist here at all. The cookie is the only
  #               server-visible signal, and it is readable precisely because the
  #               SPA needs it to be non-httpOnly.
  def mpass_session_email
    return Mpass::ProxyIdentity.normalise(current_user.email) if respond_to?(:current_user) && current_user.present?

    mpass_session_email_from_cookie
  end

  def mpass_session_email_from_cookie
    raw = cookies['cw_d_session_info']
    return nil if raw.blank?

    payload = JSON.parse(CGI.unescape(raw))
    Mpass::ProxyIdentity.normalise(payload['uid'])
  rescue JSON::ParserError
    # A malformed cookie tells us nothing about identity. Treat it as "no session"
    # rather than as a mismatch: a spurious flush would log out a valid user.
    nil
  end
end
