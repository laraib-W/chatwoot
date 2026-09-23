require 'rails_helper'

RSpec.describe Mpass::ProxyIdentity do
  def request_with(headers)
    ActionDispatch::TestRequest.create(headers)
  end

  describe '.email' do
    it 'reads X-Auth-Request-Email' do
      req = request_with('HTTP_X_AUTH_REQUEST_EMAIL' => 'Alice@Example.com')
      expect(described_class.email(req)).to eq('alice@example.com')
    end

    it 'is case- and whitespace-insensitive (mandatory test 2)' do
      req = request_with('HTTP_X_AUTH_REQUEST_EMAIL' => '  ALICE@EXAMPLE.COM  ')
      expect(described_class.email(req)).to eq('alice@example.com')
    end

    it 'falls back to X-Auth-Request-User when email is absent' do
      req = request_with('HTTP_X_AUTH_REQUEST_USER' => '847392')
      expect(described_class.email(req)).to eq("847392@#{ENV.fetch('DEFAULT_EMAIL_DOMAIN', 'askii.ai')}")
    end

    it 'returns nil when both headers are absent (mandatory test 3: absence is not logout)' do
      expect(described_class.email(request_with({}))).to be_nil
    end

    it 'returns nil when the header is whitespace only' do
      req = request_with('HTTP_X_AUTH_REQUEST_EMAIL' => '   ')
      expect(described_class.email(req)).to be_nil
    end

    it 'synthesises a bare Cognito username against DEFAULT_EMAIL_DOMAIN' do
      with_modified_env DEFAULT_EMAIL_DOMAIN: 'askii.ai' do
        req = request_with('HTTP_X_AUTH_REQUEST_EMAIL' => '847392')
        expect(described_class.email(req)).to eq('847392@askii.ai')
      end
    end
  end

  describe '.email_shaped?' do
    # Regression guard for audit row 21: this must stay indexOf-based. A
    # polynomial-backtracking regex would hang on this input instead of returning.
    it 'returns quickly on adversarial input' do
      adversarial = "!@#{'!.' * 5_000}"
      expect { Timeout.timeout(2) { described_class.email_shaped?(adversarial) } }.not_to raise_error
    end

    it 'rejects values with no @' do
      expect(described_class.email_shaped?('847392')).to be false
    end

    it 'rejects a leading or trailing @' do
      expect(described_class.email_shaped?('@example.com')).to be false
      expect(described_class.email_shaped?('alice@')).to be false
    end
  end

  describe '.display_name' do
    it 'uses the local-part when it is not numeric' do
      req = request_with({})
      expect(described_class.display_name(req, 'alice@example.com')).to eq('alice')
    end

    it 'prefers the preferred-username claim when the local-part is a bare Cognito id' do
      req = request_with('HTTP_X_AUTH_REQUEST_PREFERRED_USERNAME' => 'Alice Smith')
      expect(described_class.display_name(req, '847392@askii.ai')).to eq('Alice Smith')
    end

    # audit row 19 — a sub UUID must never reach a user-visible name field.
    it 'rejects a UUID-shaped preferred-username and falls back to the local-part' do
      req = request_with('HTTP_X_AUTH_REQUEST_PREFERRED_USERNAME' => '3f2504e0-4f89-11d3-9a0c-0305e82c3301')
      expect(described_class.display_name(req, '847392@askii.ai')).to eq('847392')
    end
  end
end
