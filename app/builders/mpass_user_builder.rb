# frozen_string_literal: true

# Resolves-or-provisions the user an mPass proxy identity asserts, then joins them
# to the canonical account.
#
# Ported from enterprise/app/builders/saml_user_builder.rb, with two deliberate
# differences:
#
#   1. NO multi-account rejection. SamlUserBuilder raises AuthenticationFailed when
#      the user belongs to another account (:21-24). The workspace-auto-join
#      contract requires join, never reject — a user legitimately spans accounts.
#   2. NO role mappings. mPass asserts identity only; role stays the regular-member
#      role. Elevation is an in-app action.
class MpassUserBuilder
  # Regular-member role. Never `administrator` — auto-provisioning must not be a
  # privilege-escalation path (workspace-auto-join/spec.md).
  DEFAULT_ROLE = 'agent'

  def initialize(email:, display_name: nil)
    @email = email
    @display_name = display_name
  end

  def perform
    @user = find_or_create_user
    auto_join_account if @user&.persisted?
    @user
  end

  private

  def find_or_create_user
    # Exact match, case-folded by User.from_email (app/models/user.rb:173).
    # Never LIKE/ILIKE on a proxy-supplied value.
    existing = User.from_email(@email)
    return adopt(existing) if existing

    create_user
  rescue ActiveRecord::RecordNotUnique
    # Concurrent first-request race: another request created the row between our
    # lookup and our insert. Fall back to a plain read; re-raise if still absent
    # rather than swallowing (proxy-auth-middleware/spec.md "Concurrent creation
    # races SHALL fall back to read").
    User.from_email(@email) || raise
  end

  def adopt(user)
    user.skip_confirmation! unless user.confirmed?
    user.save! if user.changed?
    user
  end

  def create_user
    user = User.new(
      email: @email,
      name: @display_name.presence || @email.split('@').first,
      password: SecureRandom.hex(32),
      provider: 'mpass'
    )
    user.skip_confirmation!
    user.save!
    user
  end

  # Runs on EVERY login, not only on creation — a user may have been created by an
  # earlier request that died before joining, or provisioned out of band
  # (workspace-auto-join/spec.md "auto-join SHALL run on every login").
  # Idempotent: a member already in the account is a no-op with no writes.
  def auto_join_account
    account = Account.order(created_at: :asc).first
    # No account yet: do nothing and let Chatwoot's own first-run flow create one.
    # Creating it here would race the admin provisioning the canonical account.
    return if account.blank?
    return if @user.account_users.exists?(account_id: account.id)

    AccountUser.create!(user: @user, account: account, role: DEFAULT_ROLE)
  rescue ActiveRecord::RecordNotUnique
    # Two concurrent logins for the same new user; membership already exists.
    nil
  end
end
