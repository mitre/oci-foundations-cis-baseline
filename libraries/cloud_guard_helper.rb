require_relative 'oci_backend'

class CloudGuardHelper < OciResourceBase
  name 'cloud_guard_helper'
  desc 'Helper to query Cloud Guard configuration and detector rules'

  def initialize(opts = {})
    super
    @tenancy_ocid = opts[:tenancy_ocid]
    @detector_recipe_ocid = opts[:detector_recipe_ocid]
  end

  def status
    return nil if @tenancy_ocid.to_s.empty?

    cmd = %(oci cloud-guard configuration get --compartment-id "#{@tenancy_ocid}")
    oci_cli_raw(cmd).dig('data', 'status')
  end

  def detector_rule_value(rule_id:, config_key:)
    return nil if @detector_recipe_ocid.to_s.empty?

    data = oci_cli_raw(
      %(oci cloud-guard detector-recipe-detector-rule get \
        --detector-recipe-id "#{@detector_recipe_ocid}" \
        --detector-rule-id "#{rule_id}")
    )

    configs = data.dig('data', 'details', 'configurations') || []
    match = configs.find { |c| c['config-key'] == config_key }
    match&.fetch('value', nil)
  end

  def detector_rule_enabled?(rule_id:)
    return false if @detector_recipe_ocid.to_s.empty?

    cmd = %(oci cloud-guard detector-recipe-detector-rule get \
      --detector-recipe-id "#{@detector_recipe_ocid}" \
      --detector-rule-id "#{rule_id}")

    oci_cli_raw(cmd).dig('data', 'details', 'is-enabled')
  end

  def port_list_check?(config_value:, protocol:, port:)
    config_string = config_value.to_s
    return false if config_string.empty?

    protocol_section = config_string[/#{Regexp.escape(protocol)}\s*:\s*\[([^\]]*)\]/i, 1]
    return false unless protocol_section

    protocol_section.split(/\s*,\s*/).any? do |entry|
      next false if entry.empty?

      if entry.include?('-')
        range_start_str, range_end_str = entry.split('-', 2).map(&:strip)
        next false if range_start_str.empty? || range_end_str.nil? || range_end_str.empty?

        start_port = range_start_str.to_i
        end_port = range_end_str.to_i
        Range.new(*[start_port, end_port].minmax).cover?(port)
      else
        entry.to_i == port
      end
    end
  end
end
