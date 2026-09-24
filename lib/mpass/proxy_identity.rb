# frozen_string_literal: true

# Reads the identity oauth2-proxy asserts on ForwardAuth-protected requests.
#
# These headers are trusted without verification. That is only safe under the
# deployment invariants in sso-rules-moneta/openspec/project.md:
#
#   1. Chatwoot's port is never published — traffic can only arrive via Traefik.
#   2. Traefik's strip-auth-headers middleware deletes any client-supplied
#      X-Auth-Request-* header before mpass-auth re-adds the verified values.
#   3. oauth2-proxy validates the upstream OIDC session on every ForwardAuth call.
#
# If any one of the three stops holding, every caller of this module becomes a
# spoofing vector. Do not read these headers outside an AUTH_TYPE=SSO gate.
#
module Mpass::ProxyIdentity
  EMAIL_HEADER = 'HTTP_X_AUTH_REQUEST_EMAIL'
  PREFERRED_USERNAME_HEADER = 'HTTP_X_AUTH_REQUEST_PREFERRED_USERNAME'

  UUID_SHAPE = /\A\h{8}-\h{4}-\h{4}-\h{4}-\h{12}\z/
  NUMERIC = /\A\d+\z/

  module_function

  # The single switch for every mPass behaviour in this fork. Everything SSO-only
  # asks this, so the gate cannot drift between call sites.
  def sso_mode?
    ENV.fetch('AUTH_TYPE', nil) == 'SSO'
  end

  # The normalised email this request asserts, or nil when no identity is present.
  # Absence is NOT a logout signal — internal traffic (Sidekiq, health probes,
  # direct container hits) legitimately carries no header. X-Auth-Request-User is
  # deliberately not a fallback: it is the Cognito `sub`, not the user key.
  def email(request)
    raw = normalise(request.get_header(EMAIL_HEADER))
    return nil if raw.blank?

    email_shaped?(raw) ? raw : synthesise(raw)
  end

  # Applied to BOTH sides of every comparison and to the DB lookup.
  def normalise(value)
    value.to_s.strip.downcase.presence
  end

  # indexOf-based by contract, never a regex. The canonical email-shape pattern
  # backtracks polynomially on adversarial input; CodeQL's js/polynomial-redos
  # flags it. See proxy-auth-middleware/spec.md "email-shape detection".
  def email_shaped?(value)
    idx = value.to_s.index('@')
    !idx.nil? && idx.positive? && idx < value.to_s.length - 1
  end

  # Moneta's Cognito pool returns the literal placeholder "cognito:default_val"
  # for the email claim, so identity arrives as cognito:username — a bare number.
  # Fails closed: without DEFAULT_EMAIL_DOMAIN there is no identity, never a guessed one.
  def synthesise(username)
    domain = normalise(ENV.fetch('DEFAULT_EMAIL_DOMAIN', nil))
    return nil if domain.blank?

    "#{username}@#{domain}"
  end

  # Audit row 19: a display name must never be a UUID. Prefer a real name claim
  # when the synthesised local-part is a bare Cognito ID, but reject the claim
  # when it is itself a `sub` UUID.
  def display_name(request, email_value)
    local_part = email_value.to_s.split('@').first
    return local_part unless local_part.match?(NUMERIC)

    claim = request.get_header(PREFERRED_USERNAME_HEADER).to_s.strip
    return local_part if claim.blank? || claim.match?(UUID_SHAPE)

    claim
  end
end
