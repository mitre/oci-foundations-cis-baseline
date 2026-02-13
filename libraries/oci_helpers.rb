# Shared helper methods for OCI InSpec controls.

module OciHelpers
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
  def self.format_findings(findings)
    findings.each_with_index.map { |entry, index| "[#{index + 1}]\n#{entry}" }
  end
end
