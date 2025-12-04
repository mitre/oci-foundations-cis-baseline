control '1_6' do
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
    your Domain to review is in#{' '}

    Click on the Domain to review#{' '}

    Click on Settings#{' '}

    Click on Password policy#{' '}

    Click each Password policy in the domain Ensure Previous passwords remembered is set 24 or greater
  CHECK

  desc 'fix', <<~FIX
    Go to Identity Domains: https://cloud.oracle.com/identity/domains/ Select the Compartment the Domain to remediate is in#{' '}

    Click on the Domain to remediate#{' '}

    Click on Settings#{' '}

    Click on Password policy to remediate#{' '}

    Click Edit password rules Update the number of remembered passwords in Previous passwords remembered setting to 24 or greater.
  FIX

  impact 0.5

  tag check_id: 'C-1_6'
  tag severity: 'medium'
  tag gid: 'CIS-1_6'
  tag rid: 'xccdf_cis_cis_rule_1_6'
  tag stig_id: '1.6'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'

  tag cci: [
    'CCI-001097',
    'CCI-001098',
    'CCI-002395',
    'CCI-000200',
    'CCI-000199',
    'CCI-000205',
    'CCI-000204'
  ]

  tag nist: [
    'SC-7 a',
    'SC-7 c',
    'SC-7 b',
    'IA-5 (1) (e)',
    'IA-5 (1) (d)',
    'IA-5 (1) (a)',
    'IA-5 (8)'
  ]

  # Get tenancy ID from OCI config file
  tenancy_ocid = input('tenancy_ocid')
  domain_url = `oci iam domain list --compartment-id #{tenancy_ocid} --query "data[0].url" --raw-output`.strip
  # cmd = "oci identity-domains password-policies list --endpoint #{domain_url} --all"
  cmd = "oci identity-domains password-policies list --endpoint #{domain_url} --all | ruby -rjson -e 'data = JSON.parse(STDIN.read); resources = data.dig(\"data\", \"resources\").select { |r| r[\"priority\"] || r[\"id\"] == \"PasswordPolicy\" }; puts JSON.pretty_generate({\"data\" => {\"resources\" => resources}})'"
  json_output = json(command: cmd)
  policies = json_output.params.dig('data', 'resources')

  describe 'Ensure IAM password policy prevents password reuse' do
    policies.each do |policy|
      describe "Password policy: #{policy['name']}" do
        subject { policy['num-passwords-in-history'] }
        it { should be >= 24 }
      end
    end
  end
end
