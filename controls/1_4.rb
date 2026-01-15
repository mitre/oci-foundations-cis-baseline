control '1_4' do
  title 'Ensure IAM password policy requires minimum length of 14 or greater'

  desc <<~DESC
    "Password policies are used to enforce password complexity requirements. IAM password
    policies can be used to ensure passwords are at least a certain length and are composed of
    certain characters. It is recommended the password policy require a minimum password
    length 14 characters and contain 1 non-alphabetic character (Number or “Special
    Character”). In keeping with the overall goal of having users create a password that is
    not overly weak, an eight-character minimum password length is recommended for an MFA
    account, and 14 characters for a password only account. In addition, maximum password
    length should be made as long as possible based on system/software capabilities and not
    restricted by policy. In general, it is true that longer passwords are better (harder to
    crack), but it is also true that forced password length requirements can cause user
    behavior that is predictable and undesirable. For example, requiring users to have a
    minimum 16-character password may cause them to choose repeating patterns like
    fourfourfourfour or passwordpassword that meet the requirement but aren’t hard to guess.
    Additionally, length requirements increase the chances that users will adopt other
    insecure practices, like writing them down, re-using them or storing them unencrypted in
    their documents. Password composition requirements are a poor defense against guessing
    attacks. Forcing users to choose some combination of upper-case, lower-case, numbers, and
    special characters has a negative
  DESC

  desc 'check', <<~CHECK
    Go to Identity Domains: https://cloud.oracle.com/identity/domains/ Select the Compartment
    your Domain to review is in Click on the Domain to review Click on Settings Click on
    Password policy Click each Password policy in the domain Ensure Password length (minimum)
    is greater than or equal to 14 Under The The following criteria apply to passwords
    section, ensure that the number given in Numeric (minimum) setting is 1 , or the Special
    (minimum) setting is 1 . The following criteria apply to passwords: 6. Ensure that 1 or
    more is selected for Numeric (minimum) OR Special (minimum) From Cloud Guard: To Enable
    Cloud Guard Auditing: Ensure Cloud Guard is enabled in the root compartment of the
    tenancy. For more information about enabling Cloud Guard, please look at the instructions
    included in "Ensure Cloud Guard is enabled in the root compartment of the tenancy"
    Recommendation in the "Logging and Monitoring" section. From Console: Type Cloud Guard
    into the Search box at the top of the Console. Click Cloud Guard from the “Services”
    submenu. Click Detector Recipes in the Cloud Guard menu. Click OCI Configuration Detector
    Recipe (Oracle Managed) under the Recipe Name column. Find Password policy does not meet
    complexity requirements in the Detector Rules column. Select the vertical ellipsis icon
    and chose Edit on the Password policy does not meet complexity requirements row. In the
    Edit Detector Rule window, find the Input Setting box and verify/change the Required
    password length setting to 14. Click the Save button. From CLI: Update the Password policy
    does not meet complexity requirements Detector Rule in Cloud Guard to generate Problems if
    IAM password policy isn’t configured to enforce a password length of at least 14
    characters with the following command: oci cloud-guard detector-recipe-detector-rule
    update --detector-recipe-id <insert detector recipe ocid> --detector-rule-id
    PASSWORD_POLICY_NOT_COMPLEX --details '{"configurations":[{ "configKey" :

    "passwordPolicyMinLength", "name" : "Required password length", "value" : "14", "dataType"
    : null, "values" : null }]}'
  CHECK

  desc 'fix', <<~FIX
    Go to Identity Domains: https://cloud.oracle.com/identity/domains/ Select the Compartment
    the Domain to remediate is in Click on the Domain to remediate Click on Settings Click on
    Password policy to remediate Click Edit password rules Update the Password length
    (minimum) setting to 14 or greater Under The Passwords must meet the following character
    requirements section, update the number given in Special (minimum) setting to 1 or greater
    or Under The Passwords must meet the following character requirements section, update the
    number given in Numeric (minimum) setting to 1 or greater 7. Click Save changes
  FIX

  impact 0.5

  tag check_id: 'C-1_4'
  tag severity: 'medium'
  tag gid: 'CIS-1_4'
  tag rid: 'xccdf_cis_cis_rule_1_4'
  tag stig_id: '1.4'
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

tenancy_ocid = input('tenancy_ocid')

  cmd = %(oci iam domain list --compartment-id '#{tenancy_ocid}' --all | jq '[.data[] | .url]')
  domain_urls = json(command: cmd).params || []

  min_length_values = []
  min_numeric_values = []
  min_special_values = []

  domain_urls.each do |domain_url|
    policy_cmd = %(oci identity-domains password-policies list --endpoint "#{domain_url}" --all)
    policies = json(command: policy_cmd).params.dig('data', 'resources') || []

    policies.each do |policy|
      next unless ['StandardPasswordPolicy', 'PasswordPolicy'].include?(policy['id'])

      length_value = policy.fetch('min-length', nil)
      min_length_values << (length_value.nil? ? nil : length_value.to_i)

      numeric_value = policy.fetch("min-numerals", nil)
      min_numeric_values << (numeric_value.nil? ? nil : numeric_value.to_i)

      special_value = policy.fetch('min-special-chars', nil)
      min_special_values << (special_value.nil? ? nil : special_value.to_i)
    end
  end

  describe 'Ensure IAM password policy requires at least 1 numeric or special character' do
    it 'is enabled' do
      per_policy_pass = min_numeric_values.zip(min_special_values).map do |min_numerals, min_special|
        (min_numerals.to_i >= 1) || (min_special.to_i >= 1)
      end
      expect(per_policy_pass).to all(eq(true))
    end
  end

  describe 'Ensure IAM password policy enforces a minimum password length of 14 characters' do
    subject { min_length_values }
    it { should_not be_empty }
    it { should_not include(nil) }
    it { should all(be >= 14) }
  end


  cloud_guard_check = input('cloud_guard_check')
  detector_recipe_ocid = input('detector_recipe_ocid')

  if cloud_guard_check
    tenancy_ocid = input('tenancy_ocid')
    cloud_guard = cloud_guard_helper(tenancy_ocid: tenancy_ocid, detector_recipe_ocid: detector_recipe_ocid)
    cloud_guard_status = cloud_guard.status
    cloud_guard_rule_enabled = cloud_guard.detector_rule_enabled?(rule_id: 'PASSWORD_POLICY_NOT_COMPLEX')
    cloud_guard_min_length = cloud_guard.detector_rule_value(rule_id: 'PASSWORD_POLICY_NOT_COMPLEX', config_key: 'passwordPolicyMinLength')
  end

  describe 'Cloud Guard' do
    if cloud_guard_check
      it 'is enabled' do
        expect(cloud_guard_status).to cmp 'ENABLED'
      end

      it 'detector rule "Password policy does not meet complexity requirements" is enabled' do
        expect(cloud_guard_rule_enabled).to cmp true
      end

      it 'detector rule "Password policy does not meet complexity requirements" enforces minimum password length of 14 or greater' do
        expect(cloud_guard_min_length.to_i).to be >= 14
      end
    else
      skip 'Cloud Guard check skipped. cloud_guard_check is set to false.'
    end
  end
end
