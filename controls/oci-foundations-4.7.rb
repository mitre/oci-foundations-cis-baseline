control 'oci-foundations-4.7' do
  title 'Ensure a notification is configured for user changes'

  desc <<~DESC
    It is recommended to setup an Event Rule and Notification that gets triggered when IAM
    Users are created, updated, deleted, capabilities updated, or state updated. Event Rules
    are compartment scoped and will detect events in child compartments, it is recommended to
    create the Event rule at the root compartment level. Users use or manage Oracle Cloud
    Infrastructure resources. Monitoring and alerting on changes to Users will help in
    identifying changes to the security posture.
  DESC

  desc 'check', <<~CHECK
    From Console: Using the search box to navigate to events Navigate to the rules page Select

    the Compartment that hosts the rules Find and click the Rule that handles IAM User Changes
    Click the Edit Rule button and verify that the Rule Conditions section contains a
    condition for the Service Identity and Event Types: User – Create , User – Delete , User –
    Update , User Capabilities – Update , User State – Update Verify that in the Actions
    section the Action Type contains: Notifications and that a valid Topic is referenced. From
    CLI: Find the OCID of the specific Event Rule based on Display Name and Compartment OCID
    oci events rule list --compartment-id <compartment-ocid> --query "data
    [?\"display-name\"=='<display-name>']".{"id:id"} --output table List the details of a
    specific Event Rule based on the OCID of the rule. oci events rule get --rule-id <rule-id>
    In the JSON output locate the Conditions key value pair and verify that the following
    Conditions are present: com.oraclecloud.identitycontrolplane.createuser
    com.oraclecloud.identitycontrolplane.deleteuser
    com.oraclecloud.identitycontrolplane.updateuser
    com.oraclecloud.identitycontrolplane.updateusercapabilities
    com.oraclecloud.identitycontrolplane.updateuserstate Verify the value of the is-enabled
    attribute is true In the JSON output verify that actionType is ONS and locate the topic-id
    Verify the correct topic is used by checking the topic name oci ons topic get --topic-id
    <topic-id> --query data.{"name:name"} --output table
  CHECK

  desc 'fix', <<~FIX
    From Console: Using the search box to navigate to events Navigate to the rules page Select

    the compartment that should host the rule Click Create Rule Provide a Display Name and
    Description Create a Rule Condition by selecting Identity in the Service Name Drop-down
    and selecting: User – Create , User – Delete , User – Update , User Capabilities – Update
    , User State – Update In the Actions section select Notifications as Action Type Select
    the Compartment that hosts the Topic to be used. Select the Topic to be used Optionally
    add Tags to the Rule Click Create Rule From CLI: Find the topic-id of the topic the Event
    Rule should use for sending Notifications by using the topic name and Compartment OCID oci
    ons topic list --compartment-id <compartment-ocid> --all --query "data
    [?name=='<topic-name>']".{"name:name,topic_id:\"topic-id\""} --output table Create a JSON
    file to be used when creating the Event Rule. Replace topic id, display name, description
    and compartment OCID. { "actions": { "actions": [ { "actionType": "ONS", "isEnabled":

    true, "topicId": "<topic-id>" }] }, "condition":

    "{\"eventType\":[\"com.oraclecloud.identitycontrolplane.createuser\",\"com.oraclecloud.identitycontrolplane.deleteuser\",\"com.oraclecloud.identitycontrolplane.updateuser\",\"com.oraclecloud.identitycontrolplane.updateusercapabilities\",\"com.oraclecloud.identitycontrolplane.updateuserstate\"],\"data\":{}}",
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

  tag severity: 'medium'
  tag benchmark_ref: '4.7'
  tag cis_level: 'Level 1'
  tag assessment_status: 'Automated'
  tag cis_controls: %w[4.2]

  tag cci: %w[CCI-002323]

  tag nist: ['AC-18']

  required_rule_conditions = [
    'com.oraclecloud.identitycontrolplane.createuser',
    'com.oraclecloud.identitycontrolplane.deleteuser',
    'com.oraclecloud.identitycontrolplane.updateuser',
    'com.oraclecloud.identitycontrolplane.updateusercapabilities',
    'com.oraclecloud.identitycontrolplane.updateuserstate'
  ]

  tenancy_ocid = input('tenancy_ocid')
  user_notification_topic = input('user_notification_topic')

  regions = json(command: 'oci iam region-subscription list --all').params.fetch('data', []).map { |region| region['region-name'] }.compact

  findings = []
  regions.each do |region|
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
        topic['name'] == user_notification_topic && topic['lifecycle-state'] == 'ACTIVE'
      end
    end

    findings << <<~ENTRY.chomp unless rule_present
      Region: #{region}
      Issue: Missing enabled user change notification rule(s)
    ENTRY
  end

  numbered_findings = findings.each_with_index.map do |entry, index|
    "[#{index + 1}]\n#{entry}"
  end

  describe 'IAM user change notifications' do
    it 'should have enabled event rules with an active ONS topic' do
      expect(findings).to be_empty, <<~MSG
        Non-compliant findings:

        #{numbered_findings.join("\n\n")}
      MSG
    end
  end
end
