require_relative 'oci_backend'

class OciSecurityLists < OciCollectionResourceBase
  name 'oci_security_lists'
  desc 'Lists OCI security list ingress rules across all regions and compartments.'
  example <<~EXAMPLE
    # Check for unrestricted SSH access
    findings = oci_security_lists.internet_ingress_findings(port: 22)

    describe 'Security lists' do
      it 'should not allow ingress from 0.0.0.0/0 to port 22' do
        expect(findings).to be_empty
      end
    end

    # FilterTable queries
    describe oci_security_lists.where(source: '0.0.0.0/0', protocol: '6') do
      its('count') { should eq 0 }
    end
  EXAMPLE

  filter_table_config = FilterTable.create
  filter_table_config.register_column(:regions,              field: :region)
  filter_table_config.register_column(:compartment_ids,      field: :compartment_id)
  filter_table_config.register_column(:compartment_names,    field: :compartment_name)
  filter_table_config.register_column(:security_list_names,  field: :security_list_name)
  filter_table_config.register_column(:security_list_ids,    field: :security_list_id)
  filter_table_config.register_column(:sources,              field: :source)
  filter_table_config.register_column(:protocols,            field: :protocol)
  filter_table_config.register_column(:port_mins,            field: :port_min)
  filter_table_config.register_column(:port_maxs,            field: :port_max)
  filter_table_config.install_filter_methods_on_resource(self, :table)

  def fetch_data
    rows = []

    all_regions.each do |region|
      all_compartment_ids.each do |compartment_id|
        security_lists = oci_cli(
          %(oci network security-list list --compartment-id "#{compartment_id}" --region "#{region}" --all)
        )

        security_lists.each do |sl|
          sl_id = sl['id'].to_s
          next if sl_id.empty?

          detail = oci_cli_raw(
            %(oci network security-list get --security-list-id "#{sl_id}" --region "#{region}")
          ).fetch('data', {})

          ingress_rules = detail['ingress-security-rules'] || []
          ingress_rules.each do |rule|
            port_range = rule.dig('tcp-options', 'destination-port-range')
            rows << {
              region: region,
              compartment_id: compartment_id,
              compartment_name: compartment_name_for(compartment_id),
              security_list_name: sl['display-name'],
              security_list_id: sl_id,
              source: rule['source'],
              protocol: rule['protocol'].to_s,
              port_min: port_range ? port_range['min'].to_i : nil,
              port_max: port_range ? port_range['max'].to_i : nil
            }
          end
        end
      end
    end

    rows
  end

  # Returns findings for ingress rules from 0.0.0.0/0 that expose a given port.
  # Protocol '6' = TCP. A nil port range means all ports are exposed.
  def internet_ingress_findings(port:, protocol: '6')
    table.select do |row|
      row[:source] == '0.0.0.0/0' &&
        [protocol, 'all'].include?(row[:protocol]) &&
        port_exposed?(row, port)
    end.map do |row|
      port_display = row[:port_min].nil? ? 'All TCP ports (none specified)' : "#{row[:port_min]}-#{row[:port_max]}"
      <<~ENTRY.chomp
        Region: #{row[:region]}
        Compartment Name: #{row[:compartment_name]}
        Compartment ID: #{row[:compartment_id]}
        Security List Name: #{row[:security_list_name]}
        Security List ID: #{row[:security_list_id]}
        Source: #{row[:source]}
        Destination Port Range: #{port_display}
        Issue: Ingress from 0.0.0.0/0 allows port #{port}
      ENTRY
    end
  end

  def to_s
    'OCI Security Lists'
  end

  private

  def port_exposed?(row, port)
    return true if row[:port_min].nil? # nil means all ports

    port.between?(row[:port_min], row[:port_max])
  end
end
