require_relative 'oci_backend'

class OciIdentityDomainPasswordPolicies < OciCollectionResourceBase
  name 'oci_identity_domain_password_policies'
  desc 'Fetches password policies from OCI Identity Domains.'
  example <<~EXAMPLE
    policies = oci_identity_domain_password_policies(
      tenancy_ocid: input('tenancy_ocid')
    )

    describe 'Password minimum length' do
      subject { policies.min_lengths }
      it { should all(be >= 14) }
    end

    describe 'Password expiration' do
      subject { policies.password_expires_afters }
      it { should all(be <= 365) }
    end

    describe 'Password history' do
      subject { policies.num_passwords_in_histories }
      it { should all(be >= 24) }
    end
  EXAMPLE

  filter_table_config = FilterTable.create
  filter_table_config.register_column(:domain_urls,              field: :domain_url)
  filter_table_config.register_column(:policy_ids,               field: :policy_id)
  filter_table_config.register_column(:min_lengths,              field: :min_length)
  filter_table_config.register_column(:min_numerals_list,        field: :min_numerals)
  filter_table_config.register_column(:min_special_chars_list,   field: :min_special_chars)
  filter_table_config.register_column(:password_expires_afters,  field: :password_expires_after)
  filter_table_config.register_column(:num_passwords_in_histories, field: :num_passwords_in_history)
  filter_table_config.install_filter_methods_on_resource(self, :table)

  def initialize(opts = {})
    @tenancy_ocid = opts[:tenancy_ocid]
    super
  end

  def fetch_data
    return [] if @tenancy_ocid.to_s.empty?

    rows = []
    domain_urls = fetch_domain_urls

    domain_urls.each do |domain_url|
      policies = oci_cli_raw(
        %(oci identity-domains password-policies list --endpoint "#{domain_url}" --all)
      ).dig('data', 'resources') || []

      policies.each do |policy|
        next unless %w[StandardPasswordPolicy PasswordPolicy].include?(policy['id'])

        rows << {
          domain_url: domain_url,
          policy_id: policy['id'],
          min_length: safe_int(policy['min-length']),
          min_numerals: safe_int(policy['min-numerals']),
          min_special_chars: safe_int(policy['min-special-chars']),
          password_expires_after: safe_int(policy['password-expires-after']),
          num_passwords_in_history: safe_int(policy['num-passwords-in-history'])
        }
      end
    end

    rows
  end

  def to_s
    'OCI Identity Domain Password Policies'
  end

  private

  def fetch_domain_urls
    domains = oci_cli(%(oci iam domain list --compartment-id "#{@tenancy_ocid}" --all))
    domains.map { |d| d['url'] }.compact
  rescue StandardError
    []
  end

  def safe_int(value)
    value&.to_i
  end
end
