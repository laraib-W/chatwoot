require 'rails_helper'

# Rule 2 — mandatory tests 1, 4, 5, 6. audit row 20.
RSpec.describe 'mPass session reconciliation', type: :request do
  let!(:account) { create(:account) }
  let(:user_a) { create(:user, email: 'a@askii.ai', account: account) }
  let(:user_b) { create(:user, email: 'b@askii.ai', account: account) }
  let(:sso_env) { { AUTH_TYPE: 'SSO', FRONTEND_URL: 'https://support.example.com' } }
  # Minted once: each create_new_auth_token call issues a fresh client id, so the
  # eviction assertion needs the same triple the request was made with.
  let(:token_a) { user_a.create_new_auth_token }

  describe 'Path A — document request (DashboardController)' do
    # A document request carries the cw_d_session_info cookie, not auth headers.
    def with_session_cookie(email)
      cookies['cw_d_session_info'] = CGI.escape({ uid: email }.to_json)
    end

    it 'serves normally when the proxy identity MATCHES the session (mandatory test 1)' do
      with_session_cookie('a@askii.ai')
      with_modified_env(**sso_env) do
        get '/app', headers: { 'X-Auth-Request-Email' => 'a@askii.ai' }
        expect(response).to have_http_status(:success)
      end
    end

    it 'serves normally when the header is ABSENT (mandatory test 3)' do
      with_session_cookie('a@askii.ai')
      with_modified_env(**sso_env) do
        get '/app'
        expect(response).to have_http_status(:success)
      end
    end

    it 'redirects into the handoff on MISMATCH (mandatory test 4)' do
      with_session_cookie('a@askii.ai')
      with_modified_env(**sso_env) do
        get '/app', headers: { 'X-Auth-Request-Email' => 'b@askii.ai' }
        expect(response).to redirect_to('/auth/sso/proxy-login')
      end
    end

    it 'serves normally when there is no session cookie at all (first visit)' do
      with_modified_env(**sso_env) do
        get '/app', headers: { 'X-Auth-Request-Email' => 'b@askii.ai' }
        expect(response).to have_http_status(:success)
      end
    end

    it 'does not flush on a malformed session cookie' do
      cookies['cw_d_session_info'] = 'not-json'
      with_modified_env(**sso_env) do
        get '/app', headers: { 'X-Auth-Request-Email' => 'b@askii.ai' }
        expect(response).to have_http_status(:success)
      end
    end

    it 'does nothing when AUTH_TYPE is not SSO' do
      with_session_cookie('a@askii.ai')
      with_modified_env AUTH_TYPE: nil do
        get '/app', headers: { 'X-Auth-Request-Email' => 'b@askii.ai' }
        expect(response).to have_http_status(:success)
      end
    end
  end

  describe 'Path B — XHR (Api::BaseController)' do
    it 'evicts the token and 401s on MISMATCH' do
      with_modified_env(**sso_env) do
        get "/api/v1/accounts/#{account.id}/conversations",
            headers: token_a.merge('X-Auth-Request-Email' => 'b@askii.ai')
        expect(response).to have_http_status(:unauthorized)
        expect(user_a.reload.tokens.keys).not_to include(token_a['client'])
      end
    end

    it 'leaves a MATCHING session untouched (mandatory test 1)' do
      with_modified_env(**sso_env) do
        get "/api/v1/accounts/#{account.id}/conversations",
            headers: token_a.merge('X-Auth-Request-Email' => 'a@askii.ai')
        expect(response).to have_http_status(:success)
      end
    end

    # The defect this guards: a browser-side identity switch must never evict the
    # credential of a platform or bot integration. sso-implementer Step 4 item 5.
    it 'NEVER fires for requests authenticated by an api_access_token (machine-to-machine)' do
      # user_a's API token standing in for an integration. A browser elsewhere is
      # asserting user B; that must not touch this credential.
      api_token = user_a.access_token.token
      token_a # mint the DTA triple so there is something evictable to assert on

      with_modified_env(**sso_env) do
        get "/api/v1/accounts/#{account.id}/conversations",
            headers: { 'api_access_token' => api_token, 'X-Auth-Request-Email' => 'b@askii.ai' }

        expect(response).to have_http_status(:success)
        expect(user_a.reload.tokens.keys).to include(token_a['client'])
      end
    end
  end

  describe 'identity-managed fields are gated SERVER-side (audit row 15)' do
    it 'refuses a password change under SSO' do
      with_modified_env(**sso_env) do
        put '/api/v1/profile', params: { profile: { password: 'NewPassword1!', current_password: 'Password1!' } },
                               headers: token_a
        expect(response).to have_http_status(:unprocessable_entity)
      end
    end

    it 'silently ignores an email change under SSO' do
      with_modified_env(**sso_env) do
        put '/api/v1/profile', params: { profile: { email: 'hijack@example.com' } }, headers: token_a
        expect(user_a.reload.email).to eq('a@askii.ai')
      end
    end
  end
end
