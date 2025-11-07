control '1_9' do
  title 'Ensure user customer secret keys rotate every 90 days'

  desc <<~DESC
    Object Storage provides an API to enable interoperability with Amazon S3. To use this
    Amazon S3 Compatibility API, you need to generate the signing key required to authenticate
    with Amazon S3. This special signing key is an Access Key/Secret Key pair. Oracle
    generates the Customer Secret key to pair with the Access Key. It is important to rotate
    customer secret keys at least every 90 days, as they provide the same level of object
    storage access that the user they are associated with has.
  DESC

  desc 'check', <<~CHECK
    From Console: Login to OCI Console. Select Identity & Security from the Services menu.
    
    Select Domains from the Identity menu. For each domain listed, click on the name and
    select Users . Click on an individual user under the Username heading. Click on Customer
    Secret Keys in the lower left-hand corner of the page. Ensure the date of the Customer
    Secret Key under the Created column of the Customer Secret Key is no more than 90 days
    old.
  CHECK

  desc 'fix', <<~FIX
    From Console: Login to OCI Console. Select Identity & Security from the Services menu.
    
    Select Domains from the Identity menu. For each domain listed, click on the name and
    select Users . Click on an individual user under the Username heading. Click on Customer
    Secret Keys in the lower left-hand corner of the page. Delete any Access Keys with a date
    older than 90 days under the Created column of the Customer Secret Keys.
  FIX

  impact 0.5

  tag check_id: 'C-1_9'
  tag severity: 'medium'
  tag gid: 'CIS-1_9'
  tag rid: 'xccdf_cis_cis_rule_1_9'
  tag stig_id: '1.9'
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
end
