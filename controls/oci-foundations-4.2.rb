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

  cmd = "oci iam compartment list --compartment-id '#{tenancy_ocid}' --include-root --compartment-id-in-subtree true --all"
  compartments = json(command: cmd)

  compartment_ids = compartments.params.fetch('data', []).select { |field| field['lifecycle-state'] == 'ACTIVE' }.map { |field| field['id'] }

  active_subs = []

  compartment_ids.each do |compartment_id|
    topics_cmd = "oci ons topic list --compartment-id '#{compartment_id}' --all"
    topics = json(command: topics_cmd)
    topic_data = topics.params.fetch('data', [])
    active_topics = topic_data.select { |field| field['lifecycle-state'] == 'ACTIVE' }

    active_topics.each do |topic|
      topic_id = topic['topic-id']
      subs_cmd = "oci ons subscription list --compartment-id '#{compartment_id}' --topic-id '#{topic_id}' --all"
      subs = json(command: subs_cmd)
      subs_data = subs.params.fetch('data', [])
      topic_active_subs = subs_data.select { |field| field['lifecycle-state'] == 'ACTIVE' }

      active_subs.concat(topic_active_subs) if topic_active_subs.any?
    end
  end

  describe 'Create at least one notification topic and subscription to receive monitoring alerts' do
    subject { active_subs }
    it { should_not cmp [] }
  end
end
