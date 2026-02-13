# Base classes for OCI InSpec resources
# All OCI resources use CLI-based data collection via `json(command:)`.

class OciResourceBase < Inspec.resource(1)
  name 'oci_resource_base'
  desc 'Base class for OCI InSpec resources — not used directly.'

  attr_reader :opts

  def initialize(opts = {})
    @opts = opts
    @failed_resource = false
  end

  # Executes an OCI CLI command and returns parsed JSON data array.
  def oci_cli(cmd)
    inspec.json(command: "#{cmd} 2>/dev/null").params.fetch('data', [])
  rescue StandardError => e
    Inspec::Log.warn "OCI CLI error: #{e.message}"
    []
  end

  # Executes an OCI CLI command and returns the full parsed params hash.
  def oci_cli_raw(cmd)
    inspec.json(command: "#{cmd} 2>/dev/null").params
  rescue StandardError => e
    Inspec::Log.warn "OCI CLI error: #{e.message}"
    {}
  end

  # Executes a raw shell command.
  def oci_command(cmd)
    inspec.command(cmd)
  end

  # Memoized list of subscribed region names.
  def all_regions
    @all_regions ||= oci_cli('oci iam region-subscription list --all')
                     .map { |r| r['region-name'] }
                     .compact
  end

  # Memoized list of all compartments (including root).
  def all_compartments
    @all_compartments ||= oci_cli(
      'oci iam compartment list --include-root --compartment-id-in-subtree TRUE --all'
    )
  end

  # Memoized list of compartment OCIDs.
  def all_compartment_ids
    @all_compartment_ids ||= all_compartments.map { |c| c['id'] }.compact
  end

  # Returns the compartment name for a given OCID.
  def compartment_name_for(id)
    @compartment_names ||= all_compartments.each_with_object({}) do |c, h|
      cid = c['id'].to_s
      h[cid] = c['name'] unless cid.empty?
    end
    @compartment_names[id] || 'Unknown'
  end

  def exists?
    !@failed_resource
  end
end

class OciCollectionResourceBase < OciResourceBase
  name 'oci_collection_resource_base'
  desc 'Base class for plural OCI resources with FilterTable — not used directly.'

  attr_reader :table

  def initialize(opts = {})
    super
    @table = fetch_data
  end

  def fetch_data
    raise NotImplementedError, 'Subclasses must implement fetch_data'
  end

  def to_s
    self.class.resource_name || self.class.name.to_s
  end
end
