require_relative 'oci_backend'

class OciEventRules < OciCollectionResourceBase
  name 'oci_event_rules'
  desc 'Lists OCI event rules across all regions for a given compartment.'
  example <<~EXAMPLE
    # Check that event rules cover all regions for specific event types
    rules = oci_event_rules(compartment_id: input('tenancy_ocid'))

    required = [
      'com.oraclecloud.identitycontrolplane.createpolicy',
      'com.oraclecloud.identitycontrolplane.deletepolicy',
      'com.oraclecloud.identitycontrolplane.updatepolicy'
    ]

    missing = rules.missing_regions(
      required_event_types: required,
      topic_name: input('iam_policy_notification_topic')
    )

    describe 'IAM policy change notifications' do
      it 'should cover all regions' do
        expect(missing).to be_empty
      end
    end

    # FilterTable queries
    describe oci_event_rules(compartment_id: input('tenancy_ocid'))
      .where(enabled: true) do
      its('count') { should be >= 1 }
    end
  EXAMPLE

  filter_table_config = FilterTable.create
  filter_table_config.register_column(:regions,       field: :region)
  filter_table_config.register_column(:rule_names,    field: :rule_name)
  filter_table_config.register_column(:rule_ids,      field: :rule_id)
  filter_table_config.register_column(:enabled_list,  field: :enabled)
  filter_table_config.register_column(:event_types,   field: :event_types)
  filter_table_config.register_column(:topic_names,   field: :topic_name)
  filter_table_config.register_column(:topic_actives, field: :topic_active)
  filter_table_config.install_filter_methods_on_resource(self, :table)

  def initialize(opts = {})
    @compartment_id = opts[:compartment_id]
    super
  end

  def fetch_data
    return [] if @compartment_id.to_s.empty?

    rows = []
    all_regions.each do |region|
      rules = oci_cli(
        %(oci events rule list --compartment-id "#{@compartment_id}" --region "#{region}" --all)
      )

      rules.each do |rule|
        detail = oci_cli_raw(
          %(oci events rule get --rule-id "#{rule['id']}" --region "#{region}")
        ).fetch('data', {})

        event_types = parse_event_types(detail)
        actions = detail.dig('actions', 'actions') || []

        # Create one row per ONS action (or one row with nils if no ONS actions)
        ons_actions = actions.select { |a| a['action-type'] == 'ONS' }

        if ons_actions.empty?
          rows << build_row(region, detail, event_types, nil, nil)
        else
          ons_actions.each do |action|
            topic_info = resolve_topic(action, region)
            rows << build_row(region, detail, event_types, topic_info[:name], topic_info[:active])
          end
        end
      end
    end
    rows
  end

  # Checks whether compliant rules exist in every region for the given
  # required event types and topic name.
  #
  # Returns an array of region names that are NOT covered.
  def missing_regions(required_event_types:, topic_name:)
    covered = table.select do |row|
      row[:enabled] &&
        row[:topic_name] == topic_name &&
        row[:topic_active] &&
        (required_event_types - (row[:event_types] || [])).empty?
    end.map { |r| r[:region] }.uniq

    all_regions - covered
  end

  def to_s
    'OCI Event Rules'
  end

  private

  def parse_event_types(detail)
    condition_str = detail['condition'].to_s
    return [] if condition_str.empty?

    begin
      parsed = inspec.json(content: condition_str).params
      parsed['eventType'] || []
    rescue StandardError
      []
    end
  end

  def resolve_topic(action, region)
    return { name: nil, active: false } unless action['is-enabled']

    topic_id = action['topic-id'].to_s.strip
    return { name: nil, active: false } if topic_id.empty?

    topic = oci_cli_raw(
      %(oci ons topic get --topic-id "#{topic_id}" --region "#{region}")
    ).fetch('data', {})

    { name: topic['name'], active: topic['lifecycle-state'] == 'ACTIVE' }
  end

  def build_row(region, detail, event_types, topic_name, topic_active)
    {
      region: region,
      rule_name: detail['display-name'],
      rule_id: detail['id'],
      enabled: detail['is-enabled'] == true,
      event_types: event_types,
      topic_name: topic_name,
      topic_active: topic_active == true
    }
  end
end
