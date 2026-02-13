require 'time'
require_relative 'oci_backend'

class OciVaultKeys < OciCollectionResourceBase
  name 'oci_vault_keys'
  desc 'Lists OCI Vault master encryption keys across all regions, compartments, and vaults.'

  filter_table_config = FilterTable.create
  filter_table_config.register_column(:key_ids,          field: :key_id)
  filter_table_config.register_column(:display_names,    field: :display_name)
  filter_table_config.register_column(:regions,          field: :region)
  filter_table_config.register_column(:compartment_ids,  field: :compartment_id)
  filter_table_config.register_column(:vault_names,      field: :vault_name)
  filter_table_config.register_column(:vault_ids,        field: :vault_id)
  filter_table_config.register_column(:lifecycle_states, field: :lifecycle_state)
  filter_table_config.register_column(:time_createds,    field: :time_created)
  filter_table_config.register_column(:age_days_list,    field: :age_days)
  filter_table_config.install_filter_methods_on_resource(self, :table)

  attr_reader :total_vaults, :total_keys

  def initialize(opts = {})
    @total_vaults = 0
    @total_keys = 0
    super
  end

  def fetch_data
    rows = []
    now = Time.now.utc

    all_regions.each do |region|
      all_compartment_ids.each do |compartment_id|
        vaults = oci_cli(
          %(oci kms management vault list --compartment-id "#{compartment_id}" --region "#{region}" --all)
        )

        vaults.each do |vault|
          next unless vault['lifecycle-state'] == 'ACTIVE'

          management_endpoint = vault['management-endpoint'].to_s.strip
          next if management_endpoint.empty?

          @total_vaults += 1

          keys = oci_cli(
            %(oci kms management key list --compartment-id "#{compartment_id}" --endpoint "#{management_endpoint}" --all)
          )

          keys.each do |key|
            @total_keys += 1

            created_time = begin
              Time.parse(key['time-created'].to_s).utc unless key['time-created'].to_s.empty?
            rescue StandardError
              nil
            end

            age_days = created_time ? ((now - created_time) / 86_400).floor : nil

            rows << {
              key_id: key['id'],
              display_name: key['display-name'],
              region: region,
              compartment_id: compartment_id,
              vault_name: vault['display-name'],
              vault_id: vault['id'],
              lifecycle_state: key['lifecycle-state'],
              time_created: key['time-created'],
              age_days: age_days
            }
          end
        end
      end
    end

    rows
  end

  # Returns findings for keys that are not ENABLED or are older than max_age_days.
  def non_compliant_findings(max_age_days: 365)
    now = Time.now.utc
    cutoff_time = now - (max_age_days * 86_400)

    table.reject do |row|
      state_ok = row[:lifecycle_state].to_s.strip.upcase == 'ENABLED'
      created_time = begin
        Time.parse(row[:time_created].to_s).utc unless row[:time_created].to_s.empty?
      rescue StandardError
        nil
      end
      time_ok = created_time && created_time >= cutoff_time

      state_ok && time_ok
    end.map do |row|
      <<~ENTRY.chomp
        Display Name: #{row[:display_name]}
        Key ID: #{row[:key_id]}
        Vault Name: #{row[:vault_name]}
        Vault ID: #{row[:vault_id]}
        Region: #{row[:region]}
        Compartment ID: #{row[:compartment_id]}
        Lifecycle State: #{row[:lifecycle_state]}
        Time Created: #{row[:time_created]}
        Age Days: #{row[:age_days].nil? ? 'Unknown' : row[:age_days]}
      ENTRY
    end
  end

  def to_s
    'OCI Vault Keys'
  end
end
