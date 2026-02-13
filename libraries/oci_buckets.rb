require_relative 'oci_backend'

class OciBuckets < OciCollectionResourceBase
  name 'oci_buckets'
  desc 'Lists OCI Object Storage buckets across all regions and compartments.'

  filter_table_config = FilterTable.create
  filter_table_config.register_column(:names,               field: :name)
  filter_table_config.register_column(:regions,             field: :region)
  filter_table_config.register_column(:compartment_ids,     field: :compartment_id)
  filter_table_config.register_column(:compartment_names,   field: :compartment_name)
  filter_table_config.register_column(:kms_key_ids,         field: :kms_key_id)
  filter_table_config.register_column(:versioning_statuses, field: :versioning)
  filter_table_config.install_filter_methods_on_resource(self, :table)

  def fetch_data
    rows = []

    all_regions.each do |region|
      all_compartment_ids.each do |compartment_id|
        buckets = oci_cli(
          %(oci os bucket list --compartment-id "#{compartment_id}" --region "#{region}" --all)
        )

        buckets.each do |bucket|
          bucket_name = bucket['name'].to_s
          next if bucket_name.empty?

          detail = oci_cli_raw(
            %(oci os bucket get --bucket-name "#{bucket_name}" --region "#{region}")
          ).fetch('data', {})

          rows << {
            name: bucket_name,
            region: region,
            compartment_id: compartment_id,
            compartment_name: compartment_name_for(compartment_id),
            kms_key_id: detail['kms-key-id'],
            versioning: detail['versioning'].to_s
          }
        end
      end
    end

    rows
  end

  # Returns findings for buckets missing customer-managed key encryption.
  def missing_cmk_findings
    table.select { |row| row[:kms_key_id].to_s.strip.empty? }.map do |row|
      <<~ENTRY.chomp
        Bucket Name: #{row[:name]}
        Region: #{row[:region]}
      ENTRY
    end
  end

  # Returns findings for buckets without versioning enabled.
  def missing_versioning_findings
    table.reject { |row|
      begin
        row[:versioning].casecmp('Enabled').zero?
      rescue StandardError
        false
      end
    }.map do |row|
      <<~ENTRY.chomp
        Bucket Name: #{row[:name]}
        Region: #{row[:region]}
        Compartment Name: #{row[:compartment_name]}
        Compartment ID: #{row[:compartment_id]}
        Versioning: #{row[:versioning].empty? ? 'Unknown' : row[:versioning]}
        Issue: Bucket versioning is not enabled
      ENTRY
    end
  end

  def to_s
    'OCI Buckets'
  end
end
