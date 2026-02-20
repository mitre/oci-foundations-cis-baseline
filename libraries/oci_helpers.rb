class OciHelpers < Inspec.resource(1)
  name 'oci_helpers'
  desc 'Helper resource with shared formatting methods for OCI controls.'

  # Formats an array of finding strings with numbered prefixes.
  #
  # Example output:
  #   [1]
  #   Region: us-ashburn-1
  #   Issue: Something wrong
  #
  #   [2]
  #   Region: us-phoenix-1
  #   Issue: Something else
  def format_findings(findings)
    findings.each_with_index.map { |entry, index| "[#{index + 1}]\n#{entry}" }
  end
end
