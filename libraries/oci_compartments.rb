require_relative 'oci_backend'

class OciCompartments < OciCollectionResourceBase
  name 'oci_compartments'
  desc 'Fetches all OCI compartments (including root) for the tenancy.'

  filter_table_config = FilterTable.create
  filter_table_config.register_column(:ids,   field: :id)
  filter_table_config.register_column(:names, field: :name)
  filter_table_config.install_filter_methods_on_resource(self, :table)

  def fetch_data
    all_compartments.map do |c|
      { id: c['id'], name: c['name'] }
    end
  end

  # Convenience: look up compartment name by OCID.
  def name_for(id)
    compartment_name_for(id)
  end

  def to_s
    'OCI Compartments'
  end
end
