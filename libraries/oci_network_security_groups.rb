require_relative 'oci_backend'

class OciNetworkSecurityGroups < OciCollectionResourceBase
  name 'oci_network_security_groups'
  desc 'Lists OCI network security group rules across all regions and compartments.'
  example <<~EXAMPLE
    # Check for unrestricted RDP access
    findings = oci_network_security_groups.internet_ingress_findings(port: 3389)

    describe 'Network security groups' do
      it 'should not allow ingress from 0.0.0.0/0 to port 3389' do
        expect(findings).to be_empty
      end
    end

    # FilterTable queries
    describe oci_network_security_groups
      .where(direction: 'INGRESS', source: '0.0.0.0/0') do
      its('count') { should eq 0 }
    end
  EXAMPLE

  filter_table_config = FilterTable.create
  filter_table_config.register_column(:regions,           field: :region)
  filter_table_config.register_column(:compartment_ids,   field: :compartment_id)
  filter_table_config.register_column(:compartment_names, field: :compartment_name)
  filter_table_config.register_column(:nsg_names,         field: :nsg_name)
  filter_table_config.register_column(:nsg_ids,           field: :nsg_id)
  filter_table_config.register_column(:rule_ids,          field: :rule_id)
  filter_table_config.register_column(:directions,        field: :direction)
  filter_table_config.register_column(:sources,           field: :source)
  filter_table_config.register_column(:protocols,         field: :protocol)
  filter_table_config.register_column(:port_mins,         field: :port_min)
  filter_table_config.register_column(:port_maxs,         field: :port_max)
  filter_table_config.install_filter_methods_on_resource(self, :table)

  def fetch_data
    rows = []

    all_regions.each do |region|
      all_compartment_ids.each do |compartment_id|
        nsgs = oci_cli(
          %(oci network nsg list --compartment-id "#{compartment_id}" --region "#{region}" --all)
        )

        nsgs.each do |nsg|
          nsg_id = nsg['id'].to_s
          next if nsg_id.empty?

          rules = oci_cli(
            %(oci network nsg rules list --nsg-id "#{nsg_id}" --all)
          )

          rules.each do |rule|
            port_range = rule.dig('tcp-options', 'destination-port-range')
            rows << {
              region: region,
              compartment_id: compartment_id,
              compartment_name: compartment_name_for(compartment_id),
              nsg_name: nsg['display-name'],
              nsg_id: nsg_id,
              rule_id: rule['id'],
              direction: rule['direction'],
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

  # Returns findings for INGRESS rules from 0.0.0.0/0 that expose a given port.
  def internet_ingress_findings(port:, protocol: '6')
    table.select do |row|
      row[:direction] == 'INGRESS' &&
        row[:source] == '0.0.0.0/0' &&
        row[:protocol] == protocol &&
        port_exposed?(row, port)
    end.map do |row|
      port_display = row[:port_min].nil? ? 'All TCP ports (none specified)' : "#{row[:port_min]}-#{row[:port_max]}"
      <<~ENTRY.chomp
        Region: #{row[:region]}
        Compartment Name: #{row[:compartment_name]}
        Compartment ID: #{row[:compartment_id]}
        NSG Name: #{row[:nsg_name]}
        NSG ID: #{row[:nsg_id]}
        Rule ID: #{row[:rule_id]}
        Source: #{row[:source]}
        Direction: #{row[:direction]}
        Destination Port Range: #{port_display}
        Issue: Ingress from 0.0.0.0/0 allows port #{port}
      ENTRY
    end
  end

  def to_s
    'OCI Network Security Groups'
  end

  private

  def port_exposed?(row, port)
    return true if row[:port_min].nil?

    port.between?(row[:port_min], row[:port_max])
  end
end
