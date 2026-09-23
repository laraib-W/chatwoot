# frozen_string_literal: true

# audit row 15 / Threat 5 — server-side enforcement for local-credential endpoints.
#
# The SPA route guard (v3/helpers/ssoRouteGuard.js) only removes the affordance.
# These Devise endpoints remain reachable by curl regardless of it, and
# `PUT /auth/password` does not merely change a password — it calls
# `send_auth_headers` and returns a live devise_token_auth session. That is a
# complete credential path around mPass.
#
# This is the same defect class as Chatwoot's own DISABLE_USER_PROFILE_UPDATE,
# which is honoured by the frontend and ignored by the API. A flag the UI respects
# and the server does not is not a control.
#
# 404 rather than 403: under SSO these endpoints do not conceptually exist, and a
# 403 would confirm the route is there to probe further.
# Provides the filter but does NOT register it — each controller declares its own
# `before_action :reject_local_auth_under_sso`, with an `only:` scope where the
# controller also serves non-auth actions. Auto-registering here would silently
# 404 every action on any controller that includes it.
module MpassLocalAuthGuard
  extend ActiveSupport::Concern

  private

  def reject_local_auth_under_sso
    head :not_found if ENV.fetch('AUTH_TYPE', nil) == 'SSO'
  end
end
