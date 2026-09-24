require 'rails_helper'

# audit row 15 — the SERVER half. The SPA route guard only removes the affordance;
# these endpoints stay reachable by curl. `PUT /auth/password` is the sharpest: it
# resets the password AND calls send_auth_headers, returning a live session — a
# complete credential path around mPass.
RSpec.describe 'local-credential endpoints under SSO', type: :request do
  let!(:account) { create(:account) }
  let!(:user) { create(:user, email: 'alice@askii.ai', account: account) }

  context 'when AUTH_TYPE=SSO' do
    around { |ex| with_modified_env(AUTH_TYPE: 'SSO') { ex.run } }

    it 'refuses the password-reset request' do
      post '/auth/password', params: { email: user.email }
      expect(response).to have_http_status(:not_found)
    end

    it 'refuses the password-reset submission' do
      put '/auth/password', params: { reset_password_token: 'x', password: 'NewPassword1!' }
      expect(response).to have_http_status(:not_found)
    end

    it 'does not send a reset email' do
      expect { post '/auth/password', params: { email: user.email } }
        .not_to(change { ActionMailer::Base.deliveries.size })
    end

    it 'refuses self-registration' do
      expect do
        post '/api/v1/accounts', params: {
          account_name: 'Evil Co', user_full_name: 'E', email: 'evil@example.com', password: 'Password1!'
        }
      end.not_to change(User, :count)
      expect(response).to have_http_status(:not_found)
    end

    it 'refuses installation onboarding while the flag is set' do
      Redis::Alfred.set(Redis::Alfred::CHATWOOT_INSTALLATION_ONBOARDING, true)
      post '/installation/onboarding', params: { user: { name: 'x', email: 'x@x.io', password: 'Password1!' } }
      expect(response).to have_http_status(:not_found)
    ensure
      Redis::Alfred.delete(Redis::Alfred::CHATWOOT_INSTALLATION_ONBOARDING)
    end

    it 'refuses confirmation resend' do
      post '/resend_confirmation', params: { email: user.email }
      expect(response).to have_http_status(:not_found)
    end

    # The sharpest of the set for a fork that pre-dates SSO: every account created
    # before the integration still has a working local password, and the form the
    # SPA used to render is only an affordance — this endpoint answers curl.
    it 'refuses a password login' do
      post '/auth/sign_in', params: { email: user.email, password: 'Password1!' }
      expect(response).to have_http_status(:not_found)
    end

    it 'refuses a password login sent as credential headers' do
      post '/auth/sign_in', headers: { 'email' => user.email, 'password' => 'Password1!' }
      expect(response).to have_http_status(:not_found)
    end

    it 'refuses an MFA verification' do
      post '/auth/sign_in', params: { mfa_token: 'some-token', otp_code: '123456' }
      expect(response).to have_http_status(:not_found)
    end

    # The gate must be scoped to local credentials only: the handoff re-enters this
    # same action, and a blanket 404 here would break login entirely.
    it 'still accepts the handoff token on the same endpoint' do
      token = user.generate_sso_auth_token
      post '/auth/sign_in', params: { email: user.email, sso_auth_token: token }
      expect(response).to have_http_status(:success)
    end

    it 'leaves the SSO handoff itself reachable' do
      with_modified_env(FRONTEND_URL: 'https://support.example.com') do
        get '/auth/sso/proxy-login', headers: { 'X-Auth-Request-Email' => 'alice@askii.ai' }
        expect(response).to have_http_status(:found)
      end
    end
  end

  context 'when AUTH_TYPE is unset (stock Chatwoot)' do
    around { |ex| with_modified_env(AUTH_TYPE: nil) { ex.run } }

    # Guards against the gate leaking into non-SSO deployments.
    it 'still serves the password-reset request' do
      post '/auth/password', params: { email: user.email }
      expect(response).not_to have_http_status(:not_found)
    end

    it 'still accepts a password login' do
      post '/auth/sign_in', params: { email: user.email, password: user.password }
      expect(response).to have_http_status(:success)
    end
  end
end
