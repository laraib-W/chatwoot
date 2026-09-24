require 'rails_helper'

# The per-controller guard is opt-in, so this is its choke point: it walks every route
# the auth libraries (and first-run setup) mount under AUTH_TYPE=SSO and fails when a
# controller behind one of them lacks the guard. A new local-credential surface that
# forgets `include MpassLocalAuthGuard` fails here instead of shipping open.
RSpec.describe 'local-credential route inventory under SSO', type: :request do
  let(:guards) { %i[reject_local_auth_under_sso reject_local_login_under_sso] }
  let(:local_auth_controller_pattern) { %r{\A(devise_token_auth|devise_overrides|devise|installation|auth)/} }

  # Reachable under SSO without the guard, each for a stated reason.
  let(:not_local_credentials) { %w[devise_overrides/token_validations] }
  let(:known_open) do
    {
      'devise_token_auth/registrations' => 'apps/chatwoot/security.md G7 — PUT /auth sets a password without the current one',
      'devise_overrides/omniauth_callbacks' => 'apps/chatwoot/security.md G10 — gate OmniAuth under SSO',
      'devise_token_auth/omniauth_callbacks' => 'apps/chatwoot/security.md G10',
      'devise/passwords' => 'super-admin Devise defaults (devise_for :super_admins has no skip:)',
      'devise/confirmations' => 'super-admin Devise defaults',
      'devise/registrations' => 'super-admin Devise defaults',
      'devise/omniauth_callbacks' => 'super-admin Devise defaults'
    }
  end

  around do |example|
    with_modified_env(AUTH_TYPE: 'SSO') do
      Rails.application.reload_routes!
      example.run
    end
  ensure
    Rails.application.reload_routes!
  end

  def local_auth_controllers
    Rails.application.routes.routes
         .filter_map { |route| route.defaults[:controller] }
         .grep(local_auth_controller_pattern).uniq
  end

  it 'guards every local-credential controller the routes expose' do
    unguarded = (local_auth_controllers - not_local_credentials - known_open.keys).reject do |name|
      filters = "#{name.camelize}Controller".constantize._process_action_callbacks.map(&:filter)
      filters.intersect?(guards)
    end

    expect(unguarded).to be_empty
  end

  # Prefixes miss endpoints like POST /api/v2/accounts, so also find controllers by
  # what they do: anything that issues a devise_token_auth session must be gated.
  it 'guards every controller that issues a session, wherever it is mounted' do
    issuers = Dir[Rails.root.join('app/controllers/**/*_controller.rb')].select do |file|
      File.read(file).match?(/\b(send_auth_headers|create_new_auth_token|create_token)\b/)
    end
    names = issuers.map { |file| file[%r{app/controllers/(.+)_controller\.rb\z}, 1] }

    unguarded = (names - not_local_credentials - known_open.keys).reject do |name|
      filters = "#{name.camelize}Controller".constantize._process_action_callbacks.map(&:filter)
      filters.intersect?(guards)
    end

    expect(unguarded).to be_empty
  end
end
