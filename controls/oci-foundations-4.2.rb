control 'oci-foundations-4.2' do
  title 'Create at least one notification topic and subscription to receive monitoring alerts'

  desc <<~DESC
    Notifications provide a multi-channel messaging service that allow users and applications
    to be notified of events of interest occurring within OCI. Messages can be sent via eMail,
    HTTPs, PagerDuty, Slack or the OCI Function service. Some channels, such as eMail require
    confirmation of the subscription before it becomes active. Creating one or more
    notification topics allow administrators to be notified of relevant changes made to OCI
    infrastructure.
  DESC

  desc 'check', <<~CHECK
    From Console: Go to the Notifications Service page:

    https://console.us-ashburn-1.oraclecloud.com/notification/topics Select the Compartment
    that hosts the notifications Find and click the Topic relevant to your monitoring alerts.
    Ensure a valid active subscription is shown. From CLI: List the topics in the Compartment
    that hosts the notifications oci ons topic list --compartment-id <compartment OCID> --all
    Note the OCID of the monitoring topic(s) using the topic-id field of the returned JSON and
    use it to list the subscriptions oci ons subscription list --compartment-id <compartment
    OCID> --topic-id <topic OCID> --all Ensure at least one active subscription is returned
  CHECK

  desc 'fix', <<~FIX
    From Console: Go to the Notifications Service page:

    https://console.us-ashburn-1.oraclecloud.com/notification/topics Select the Compartment
    that hosts the notifications Click Create Topic Set the name to something relevant Set the
    description to describe the purpose of the topic Click Create Click the newly created
    topic Click Create Subscription Choose the correct protocol Complete the correct
    parameter, for instance email address Click Create From CLI: Create a topic in a
    compartment oci ons topic create --name <topic name> --description <topic description>
    --compartment-id <compartment OCID> Note the OCID of the topic using the topic-id field of
    the returned JSON and use it to create a new subscription oci ons subscription create
    --compartment-id <compartment OCID> --topic-id <topic OCID> --protocol <protocol>
    --subscription-endpoint <subscription endpoint> The returned JSON includes the id of the
    subscription .
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    "There is no performance
  POTENTIAL_IMPACTS

  impact 0.5

  tag severity: 'medium'
  tag benchmark_ref: '4.2'
  tag cis_level: 'Level 1'
  tag assessment_status: 'Automated'
  tag cis_controls: %w[8.2 8.11]

  tag cci: %w[CCI-000123 CCI-000133]

  tag nist: ['AU-2', 'AU-6']

  tenancy_ocid = input('tenancy_ocid')

  regions_response = json(command: 'oci iam region-subscription list --all')
  regions_data = regions_response.params.fetch('data', [])
  regions = regions_data.map { |region| region['region-name'] }.compact

  compartments_response = json(
    command: %(oci iam compartment list --compartment-id "#{tenancy_ocid}" --include-root --compartment-id-in-subtree TRUE --all 2>/dev/null)
  )
  compartments_data = compartments_response.params.fetch('data', [])
  active_compartments = compartments_data.select { |compartment| compartment['lifecycle-state'] == 'ACTIVE' }

  active_subscription_entries = []

  regions.each do |region|
    active_compartments.each do |compartment|
      compartment_id = compartment['id']
      compartment_name = compartment['name']
      next if compartment_id.to_s.empty?

      topics_response = json(command: %(oci ons topic list --compartment-id "#{compartment_id}" --region "#{region}" --all 2>/dev/null))
      topics_data = topics_response.params.fetch('data', [])
      active_topics = topics_data.select { |topic| topic['lifecycle-state'] == 'ACTIVE' }

      active_topics.each do |topic|
        topic_id = topic['topic-id']
        next if topic_id.to_s.empty?

        subscriptions_response = json(
          command: %(oci ons subscription list --compartment-id "#{compartment_id}" --topic-id "#{topic_id}" --region "#{region}" --all 2>/dev/null)
        )
        subscriptions_data = subscriptions_response.params.fetch('data', [])
        active_subscriptions = subscriptions_data.select { |subscription| subscription['lifecycle-state'] == 'ACTIVE' }

        active_subscriptions.each do |subscription|
          active_subscription_entries << <<~ENTRY.chomp
            Region: #{region}
            Compartment Name: #{compartment_name}
            Compartment ID: #{compartment_id}
            Topic Name: #{topic['name']}
            Topic ID: #{topic_id}
            Subscription Protocol: #{subscription['protocol']}
            Subscription Endpoint: #{subscription['endpoint']}
            Subscription ID: #{subscription['id']}
          ENTRY
        end
      end
    end
  end

  findings = []
  if active_subscription_entries.empty?
    findings << <<~ENTRY.chomp
      Issue: No ACTIVE ONS subscription found for monitoring alerts.
      Active Compartment Count: #{active_compartments.length}
      Searched Regions: #{regions.empty? ? 'None' : regions.join(', ')}
    ENTRY
  end

  numbered_findings = findings.each_with_index.map do |entry, index|
    "[#{index + 1}]\n#{entry}"
  end

  describe 'Notification topics and subscriptions' do
    it 'should include at least one ACTIVE subscription to receive monitoring alerts' do
      expect(findings).to be_empty, <<~MSG
        Non-compliant findings:

        #{numbered_findings.join("\n\n")}
      MSG
    end
  end
end
