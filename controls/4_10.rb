control '4_10' do
  title 'Ensure a notification is configured for security list changes'

  desc <<~DESC
    It is recommended to setup an Event Rule and Notification that gets triggered when
    security lists are created, updated or deleted. Event Rules are compartment scoped and
    will detect events in child compartments, it is recommended to create the Event rule at
    the root compartment level. Security Lists control traffic flowing into and out of Subnets
    within a Virtual Cloud Network. Monitoring and alerting on changes to Security Lists will
    help in identifying changes to these security controls.
  DESC

  desc 'check', <<~CHECK
    From Console: Go to the Events Service page: https://cloud.oracle.com/events/rules Select

    the Compartment that hosts the rules Find and click the Rule that handles Security List
    Changes (if any) Click the Edit Rule button and verify that the RuleConditions section
    contains a condition for the Service Networking and Event Types: Security List – Change
    Compartment , Security List – Create , Security List - Delete and Security List – Update
    Verify that in the Actions section the Action Type contains: Notifications and that a
    valid Topic is referenced. From CLI: Find the OCID of the specific Event Rule based on
    Display Name and Compartment OCID oci events rule list --compartment-id <compartment-ocid>
    --query "data [?\"display-name\"=='<display-name>']".{"id:id"} --output table List the
    details of a specific Event Rule based on the OCID of the rule. oci events rule get
    --rule-id <rule-ocid> In the JSON output locate the Conditions key value pair and verify
    that the following Conditions are present:

    com.oraclecloud.virtualnetwork.changesecuritylistcompartment
    com.oraclecloud.virtualnetwork.createsecuritylist
    com.oraclecloud.virtualnetwork.deletesecuritylist
    com.oraclecloud.virtualnetwork.updatesecuritylist Verify the value of the is-enabled
    attribute is true In the JSON output verify that actionType is ONS and locate the topic-id
    Verify the correct topic is used by checking the topic name oci ons topic get --topic-id
    <topic-id> --query data.{"name:name"} --output table
  CHECK

  desc 'fix', <<~FIX
    From Console: Go to the Events Service page: https://cloud.oracle.com/events/rules Select

    the compartment that should host the rule Click Create Rule Provide a Display Name and
    Description Create a Rule Condition by selecting Networking in the Service Name Drop-down
    and selecting Security List – Change Compartment , Security List – Create , Security List
    - Delete and Security List – Update In the Actions section select Notifications as Action
    Type Select the Compartment that hosts the Topic to be used. Select the Topic to be used
    Optionally add Tags to the Rule Click Create Rule From CLI: Find the topic-id of the topic
    the Event Rule should use for sending Notifications by using the topic name and
    Compartment OCID oci ons topic list --compartment-id <compartment-ocid> --all --query
    "data [?name=='<topic-name>']".{"name:name,topic_id:\"topic-id\""} --output table Create a
    JSON file to be used when creating the Event Rule. Replace topic-id, display name,
    description and compartment OCID. { "actions": { "actions": [ { "actionType": "ONS",
    "isEnabled": true, "topicId": "<topic-id>" }] }, "condition":

    "{\"eventType\":[\"com.oraclecloud.virtualnetwork.changesecuritylistcompartment\",\"com.oraclecloud.virtualnetwork.createsecuritylist\",\"com.oraclecloud.virtualnetwork.deletesecuritylist\",\"com.oraclecloud.virtualnetwork.updatesecuritylist\"],\"data\":{}}",
    "displayName": "<display-name>", "description": "<description>", "isEnabled": true,
    "compartmentId": "<compartment-ocid>" } Create the actual event rule oci events rule
    create --from-json file://event_rule.json Note in the JSON returned that it lists the
    parameters specified in the JSON file provided and that there is an OCID provided for the
    Event Rule
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    "There is no performance
  POTENTIAL_IMPACTS

  impact 0.5

  tag check_id: 'C-4_10'
  tag severity: 'medium'
  tag gid: 'CIS-4_10'
  tag rid: 'xccdf_cis_cis_rule_4_10'
  tag stig_id: '4.1'
  tag gtitle: '<GroupDescription></GroupDescription>'
  tag 'documentable'

  tag cci: [
    'CCI-002323',
    'CCI-000364',
    'CCI-000366',
    'CCI-000381',
    'CCI-001199',
    'CCI-000540',
    'CCI-002472'
  ]

  tag nist: [
    'AC-18 a',
    'CM-6 a',
    'CM-6 b',
    'CM-7 a',
    'SC-28',
    'CP-9 (d)',
    'SC-28'
  ]

  required_rule_conditions = [
    'com.oraclecloud.virtualnetwork.changesecuritylistcompartment',
    'com.oraclecloud.virtualnetwork.createsecuritylist',
    'com.oraclecloud.virtualnetwork.deletesecuritylist',
    'com.oraclecloud.virtualnetwork.updatesecuritylist'
  ]

  tenancy_ocid = input('tenancy_ocid')
  security_list_notification_topic = input('security_list_notification_topic')

  regions = json(command: 'oci iam region-subscription list --all').params.fetch('data', []).map { |region| region['region-name'] }.compact

  findings = regions.each_with_object([]) do |region, missing|
    rules = json(command: %(oci events rule list --compartment-id "#{tenancy_ocid}" --region "#{region}" --all 2>/dev/null)).params.fetch('data', [])

    rule_present = rules.any? do |rule|
      rule_details = json(command: %(oci events rule get --rule-id "#{rule['id']}" --region "#{region}" 2>/dev/null)).params.fetch('data', {})

      next false unless rule_details['is-enabled']

      condition_data = begin
        json(content: rule_details['condition'].to_s).params
      rescue StandardError
        {}
      end

      event_types = condition_data['eventType']
      next false unless (required_rule_conditions - event_types).empty?

      actions = rule_details.dig('actions', 'actions') || []
      actions.any? do |action|
        next false unless action['action-type'] == 'ONS' && action['is-enabled']

        topic_id = action['topic-id']
        next false if topic_id.to_s.strip.empty?

        topic = json(command: %(oci ons topic get --topic-id "#{topic_id}" --region "#{region}" 2>/dev/null)).params.fetch('data', {})
        topic['name'] == security_list_notification_topic && topic['lifecycle-state'] == 'ACTIVE'
      end
    end

    missing << { region: region, issue: 'Missing enabled security list change notification rule(s)' } unless rule_present
  end

  describe 'Ensure a notification is configured for security list changes' do
    subject { findings }
    it { should be_empty }
  end
end
