control 'oci-foundations-1.5' do
  title 'Ensure IAM password policy expires passwords within 365 days'

  desc <<~DESC
    IAM password policies can require passwords to be rotated or expired after a given number
    of days. It is recommended that the password policy expire passwords after 365 and are
    changed immediately based on events. Excessive password expiration requirements do more
    harm than good, because these requirements make users select predictable passwords,
    composed of sequential words and numbers that are closely related to each other.10 In
    these cases, the next password can be predicted based on the previous one (incrementing a
    number used in the password for example). Also, password expiration requirements offer no
    containment benefits because attackers will often use credentials as soon as they
    compromise them. Instead, immediate password changes should be based on key events
    including, but not limited to: Indication of compromise Change of user roles When a user
    leaves the organization. Not only does changing passwords every few weeks or months
    frustrate the user, it’s been suggested that it does more harm than good, because it could
    lead to bad practices by the user such as adding a character to the end of their existing
    password. In addition, we also recommend a yearly password change. This is primarily
    because for all their good intentions users will share credentials across accounts.
    Therefore, even if a breach is publicly identified, the user may not see this
    notification, or forget they have an account on that site. This could leave a shared
    credential vulnerable indefinitely. Having an organizational policy of a 1-year (annual)
    password expiration is a reasonable compromise to mitigate this with minimal user burden.
  DESC

  desc 'check', <<~CHECK
    Go to Identity Domains: https://cloud.oracle.com/identity/domains/ Select the Compartment
    your Domain to review is in Click on the Domain to review Click on Settings Click on
    Password policy Click each Password policy in the domain Ensure Expires after (days) is
    less than or equal to 365 days
  CHECK

  desc 'fix', <<~FIX
    Go to Identity Domains: https://cloud.oracle.com/identity/domains/ Select the Compartment
    the Domain to remediate is in Click on the Domain to remediate Click on Settings Click on
    Password policy to remediate Click Edit password rules Change Expires after (days) to 365
  FIX

  impact 0.5

  tag severity: 'medium'
  tag benchmark_ref: '1.5'
  tag cis_level: 'Level 1'
  tag assessment_status: 'Manual'
  tag cis_controls: %w[4.1 5.2]

  tag cci: %w[CCI-000364 CCI-000200]

  tag nist: ['CM-6', 'IA-5']

  tenancy_ocid = input('tenancy_ocid')

  policies = oci_identity_domain_password_policies(tenancy_ocid: tenancy_ocid)
  expires_after_values = policies.password_expires_afters

  describe 'Ensure IAM password policy expires passwords within 365 days' do
    subject { expires_after_values }

    it { should_not cmp [] }
    it { should_not include(nil) }
    it { should all(be <= 365) }
  end
end
