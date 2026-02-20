control 'oci-foundations-1.6' do
  title 'Ensure IAM password policy prevents password reuse'

  desc <<~DESC
    IAM password policies can prevent the reuse of a given password by the same user. It is
    recommended the password policy prevent the reuse of passwords. Enforcing password history
    ensures that passwords are not reused in for a certain period of time by the same user. If
    a user is not allowed to use last 24 passwords, that window of time is greater. This helps
    maintain the effectiveness of password security.
  DESC

  desc 'check', <<~CHECK
    Go to Identity Domains: https://cloud.oracle.com/identity/domains/ Select the Compartment
    your Domain to review is in Click on the Domain to review Click on Settings Click on
    Password policy Click each Password policy in the domain Ensure Previous passwords
    remembered is set 24 or greater
  CHECK

  desc 'fix', <<~FIX
    Go to Identity Domains: https://cloud.oracle.com/identity/domains/ Select the Compartment
    the Domain to remediate is in Click on the Domain to remediate Click on Settings Click on
    Password policy to remediate Click Edit password rules Update the number of remembered
    passwords in Previous passwords remembered setting to 24 or greater.
  FIX

  impact 0.5

  tag severity: 'medium'
  tag benchmark_ref: '1.6'
  tag cis_level: 'Level 1'
  tag assessment_status: 'Manual'
  tag cis_controls: %w[5.2]

  tag cci: %w[CCI-000200]

  tag nist: ['IA-5']

  tenancy_ocid = input('tenancy_ocid')

  policies = oci_identity_domain_password_policies(tenancy_ocid: tenancy_ocid)
  history_values = policies.num_passwords_in_histories

  describe 'Ensure IAM password policy prevents password reuse' do
    subject { history_values }
    it { should_not cmp [] }
    it { should_not include(nil) }
    it { should all(be >= 24) }
  end
end
