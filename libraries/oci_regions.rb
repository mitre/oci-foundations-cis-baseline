require_relative 'oci_backend'

class OciRegions < OciCollectionResourceBase
  name 'oci_regions'
  desc 'Fetches the list of subscribed OCI regions.'
  example <<~EXAMPLE
    describe oci_regions do
      its('names') { should include 'us-ashburn-1' }
      its('count') { should be >= 1 }
    end

    oci_regions.names.each do |region|
      describe "Region \#{region}" do
        it { should_not be_nil }
      end
    end
  EXAMPLE

  filter_table_config = FilterTable.create
  filter_table_config.register_column(:names, field: :name)
  filter_table_config.install_filter_methods_on_resource(self, :table)

  def fetch_data
    all_regions.map { |name| { name: name } }
  end

  def to_s
    'OCI Regions'
  end
end
