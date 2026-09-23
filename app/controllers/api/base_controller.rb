class Api::BaseController < ApplicationController
  include AccessTokenAuthHelper
  include MpassSessionReconciliation
  respond_to :json
  before_action :authenticate_access_token!, if: :authenticate_by_access_token?
  before_action :validate_bot_access_token!, if: :authenticate_by_access_token?
  before_action :authenticate_user!, unless: :authenticate_by_access_token?
  # Rule 2, Path B — XHR backstop. Deliberately NOT applied to the access-token
  # branches above: platform and bot integrations carry no user session, so there
  # is nothing to flush, and evicting their credential because a *browser*
  # elsewhere switched users would break unrelated integrations.
  # audit row 20; sso-implementer Step 4 item 5.
  before_action :flush_stale_mpass_session, unless: :authenticate_by_access_token?

  private

  # A redirect cannot resolve a mismatch mid-XHR (axios would follow it and receive
  # HTML), so evict this client's token and answer 401. The SPA's 401 handler
  # hard-navigates, which re-enters the handoff as the incoming identity.
  def flush_stale_mpass_session
    return unless mpass_identity_mismatch?

    client_id = request.headers['client']
    if client_id.present? && current_user.respond_to?(:tokens)
      current_user.tokens.delete(client_id)
      current_user.save!
    end
    head :unauthorized
  end

  def authenticate_by_access_token?
    request.headers[:api_access_token].present? || request.headers[:HTTP_API_ACCESS_TOKEN].present?
  end

  def check_authorization(model = nil)
    model ||= controller_name.classify.constantize

    authorize(model)
  end

  def check_admin_authorization?
    raise Pundit::NotAuthorizedError unless Current.account_user.administrator?
  end
end
