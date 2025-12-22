control '1_5' do
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
    Go to Identity Domains: https://cloud.oracle.com/identity/domains/
    Select the Compartment your Domain to review is in.
    Click on the Domain to review.
    Click on Settings.
    Click on Password policy.
    Click each Password policy in the domain and ensure Expires after (days) is
    less than or equal to 365 days.
  CHECK

  desc 'fix', <<~FIX
    Go to Identity Domains: https://cloud.oracle.com/identity/domains/
    Select the Compartment the Domain to remediate is in.
    Click on the Domain to remediate.
    Click on Settings.
    Click on Password policy to remediate.
    Click Edit password rules.
    Change Expires after (days) to 365.
  FIX

  impact 0.5

  tag check_id: 'C-1_5'
  tag severity: 'medium'
  tag gid: 'CIS-1_5'
  tag rid: 'xccdf_cis_cis_rule_1_5'
  tag stig_id: '1.5'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'

  tag cci: [
    'CCI-000364',
    'CCI-000365',
    'CCI-000366',
    'CCI-000421',
    'CCI-001097',
    'CCI-001098',
    'CCI-002395',
    'CCI-002110',
    'CCI-002111',
    'CCI-002112',
    'CCI-000012',
    'CCI-000200',
    'CCI-000199',
    'CCI-000205',
    'CCI-000204'
  ]

  tag nist: [
    'CM-6 a',
    'CM-6 a',
    'CM-6 b',
    'CM-9 a',
    'SC-7 a',
    'SC-7 c',
    'SC-7 b',
    'AC-2 a',
    'AC-2 a',
    'AC-2 b',
    'AC-2 j',
    'IA-5 (1) (e)',
    'IA-5 (1) (d)',
    'IA-5 (1) (a)',
    'IA-5 (8)'
  ]
 tenancy_ocid =input('tenancy_ocid')
  
  domains_cmd = "oci iam domain list --compartment-id #{tenancy_ocid} --query 'data[].url' --raw-output"
  domain_urls = `#{domains_cmd}`.strip.split("\n")

  all_policies = []
  
  domain_urls.each do |domain_url|
    cmd = "oci identity-domains password-policies list --endpoint #{domain_url} --all | ruby -rjson -e 'data = JSON.parse(STDIN.read); resources = data.dig(\"data\", \"resources\").select { |r| r[\"priority\"] || r[\"id\"] == \"PasswordPolicy\" }; puts JSON.pretty_generate({\"data\" => {\"resources\" => resources}})'"
    json_output = json(command: cmd)
    policies_from_domain = json_output.params.dig('data', 'resources')
    all_policies.concat(policies_from_domain) if policies_from_domain
  end

  policies = all_policies

  all_expiry = policies.map do |p|
    next unless p.is_a?(Hash)
    value = p['expires-after']/i || p['expires after']/i || p['expiresafter']/i
    value.to_i if value
  end.compact.max || 0

  describe 'Ensure IAM password policy expires passwords within 365 days' do
    subject { max_expiry }
    it { should be <= 365 }
  end 
end
