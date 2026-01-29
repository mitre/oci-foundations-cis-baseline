#!/usr/bin/env ruby
# frozen_string_literal: true

# Script to reformat InSpec control files for better readability
# Usage: ruby format_controls.rb [file_or_directory]
#   ruby format_controls.rb controls/1_1.rb           # Format single file
#   ruby format_controls.rb controls/                 # Format all files in directory
#   ruby format_controls.rb                           # Format all files in ./controls/

require 'fileutils'

class ControlFormatter
  WRAP_WIDTH = 90

  def initialize(file_path)
    @file_path = file_path
    @content = File.read(file_path)
    @output_lines = []
  end

  def format
    if already_formatted?
      puts "⊘ Skipped (already formatted): #{@file_path}"
      return false
    end

    parse_control
    write_output
    true
  end

  def already_formatted?
    # Check for heredoc syntax which indicates it's already formatted
    return true if @content.match?(/<<~DESC/) || @content.match?(/<<~CHECK/) || @content.match?(/<<~FIX/)

    # Check for multi-line array formatting (cci or nist tags)
    # Looking for pattern like:
    #   tag cci: [
    #     'CCI-000056',
    array_pattern = /tag\s+(cci|nist):\s+\[\s*\n\s+['"][^'"]+['"]/m
    return true if @content.match?(array_pattern)

    false
  end

  private

  def parse_control
    # Extract components using regex
    control_id = extract_quoted_value(/control\s+["'](.+?)["']/)
    title = extract_quoted_value(/title\s+["'](.+?)["']/)
    desc = extract_desc_value(/desc\s+(.+?)(?=\s+desc\s+["']|impact|tag)/m)
    desc_check = extract_desc_value(/desc\s+["']check["'],?\s+(.+?)(?=\s+desc\s+["']|impact|tag)/m)
    desc_fix = extract_desc_value(/desc\s+["']fix["'],?\s+(.+?)(?=\s+desc\s+["']|impact|tag)/m)
    desc_impacts = extract_desc_value(/desc\s+["']potential_impacts["'],?\s+(.+?)(?=\s+desc\s+["']|impact|tag)/m)
    impact = extract_value(/impact\s+([\d.]+)/)
    tags = extract_tags

    # Build formatted output
    @output_lines << "control '#{control_id}' do"
    @output_lines << "  title '#{escape_single_quotes(title)}'"
    @output_lines << ''

    add_desc_block('desc', desc) if desc
    add_desc_block('check', desc_check) if desc_check
    add_desc_block('fix', desc_fix) if desc_fix
    add_desc_block('potential_impacts', desc_impacts) if desc_impacts

    @output_lines << "  impact #{impact}"
    @output_lines << ''

    add_tags(tags)

    @output_lines << 'end'
  end

  def extract_quoted_value(regex)
    match = @content.match(regex)
    return nil unless match

    match[1]
  end

  def extract_value(regex)
    match = @content.match(regex)
    return nil unless match

    match[1]
  end

  def extract_desc_value(regex)
    match = @content.match(regex)
    return nil unless match

    raw = match[1]
    # Remove surrounding quotes and %q()
    raw = raw.strip
    raw = raw[1..-2] if raw.start_with?('"', "'") && raw.end_with?('"', "'")
    raw = raw[3..-2] if raw.start_with?('%q(') && raw.end_with?(')')
    raw.strip
  end

  def extract_tags
    tags = {}

    # Extract all tag lines
    @content.scan(/tag\s+(.+)/).each do |match|
      tag_line = match[0].strip

      # Handle different tag formats
      if tag_line =~ /^["'](\w+)["']$/
        # tag "documentable"
        tags[tag_line.gsub(/["']/, '')] = true
      elsif tag_line =~ /^(\w+):\s*(.+)$/
        # tag check_id: "C-1_1"
        key = ::Regexp.last_match(1)
        value = ::Regexp.last_match(2).strip

        # Parse array or single value
        if value.start_with?('[')
          # Parse array
          array_content = value[1..-2] # Remove [ and ]
          tags[key] = array_content.scan(/["']([^"']+)["']/).flatten
        else
          # Single value
          tags[key] = value.gsub(/["']/, '')
        end
      end
    end

    tags
  end

  def add_desc_block(type, content)
    return unless content

    @output_lines << if type == 'desc'
                       '  desc <<~DESC'
                     else
                       "  desc '#{type}', <<~#{type.upcase}"
                     end

    wrapped_lines = wrap_text(content)
    wrapped_lines.each { |line| @output_lines << "    #{line}" }

    @output_lines << if type == 'desc'
                       '  DESC'
                     else
                       "  #{type.upcase}"
                     end
    @output_lines << ''
  end

  def wrap_text(text)
    # Clean up the text
    text = text.gsub(/\s+/, ' ').strip

    lines = []
    current_line = ''

    text.split(' ').each do |word|
      test_line = current_line.empty? ? word : "#{current_line} #{word}"

      if test_line.length <= WRAP_WIDTH
        current_line = test_line
      else
        lines << current_line unless current_line.empty?
        current_line = word
      end
    end

    lines << current_line unless current_line.empty?

    # Add blank lines for better readability at logical breaks
    formatted_lines = []
    lines.each_with_index do |line, idx|
      formatted_lines << line

      # Add blank line after certain patterns
      next unless line.match?(/:\s*$/) || # Ends with colon
                  line.match?(/^(From CLI|From Console|Note:|Example)/i) || # Section headers
                  (idx < lines.length - 1 && lines[idx + 1].match?(/^(From CLI|From Console|Note:|Example)/i))

      formatted_lines << ''
    end

    formatted_lines
  end

  def add_tags(tags)
    # Define tag order
    simple_tags = []
    hash_tags = {}
    array_tags = {}

    tags.each do |key, value|
      if value == true
        simple_tags << key
      elsif value.is_a?(Array)
        array_tags[key] = value
      else
        hash_tags[key] = value
      end
    end

    # Add simple hash tags first in specific order
    tag_order = %w[check_id severity gid rid stig_id gtitle]
    tag_order.each do |key|
      next unless hash_tags[key]

      @output_lines << "  tag #{key}: '#{hash_tags[key]}'"
      hash_tags.delete(key)
    end

    # Add remaining hash tags
    hash_tags.each do |key, value|
      @output_lines << "  tag #{key}: '#{value}'"
    end

    # Add simple tags
    simple_tags.each do |tag|
      @output_lines << "  tag '#{tag}'"
    end

    @output_lines << '' unless array_tags.empty?

    # Add array tags
    array_tags.each do |key, values|
      @output_lines << "  tag #{key}: ["
      values.each_with_index do |val, idx|
        comma = idx < values.length - 1 ? ',' : ''
        @output_lines << "    '#{val}'#{comma}"
      end
      @output_lines << '  ]'
      @output_lines << '' # Blank line after each array tag
    end

    # Remove trailing blank line if present
    @output_lines.pop if @output_lines.last == ''
  end

  def escape_single_quotes(text)
    text.gsub("'", "\\\\'")
  end

  def write_output
    File.write(@file_path, "#{@output_lines.join("\n")}\n")
    puts "✓ Formatted: #{@file_path}"
    true
  rescue StandardError => e
    puts "✗ Error formatting #{@file_path}: #{e.message}"
    nil
  end
end

# Main script logic
def format_files(path)
  if File.directory?(path)
    files = Dir.glob(File.join(path, '*.rb'))
    puts "Found #{files.length} control files\n\n"

    formatted_count = 0
    skipped_count = 0
    error_count = 0

    files.sort.each do |file|
      result = ControlFormatter.new(file).format
      if result == true
        formatted_count += 1
      elsif result == false
        skipped_count += 1
      else
        error_count += 1
      end
    end

    puts "\n#{'=' * 60}"
    puts 'Summary:'
    puts "  ✓ Formatted: #{formatted_count} files"
    puts "  ⊘ Skipped:   #{skipped_count} files (already formatted)"
    puts "  ✗ Errors:    #{error_count} files" if error_count > 0
    puts '=' * 60
  elsif File.file?(path)
    ControlFormatter.new(path).format
  else
    puts "Error: #{path} is not a valid file or directory"
    exit 1
  end
end

# Script entry point
if __FILE__ == $PROGRAM_NAME
  path = ARGV[0] || 'controls/'

  unless File.exist?(path)
    puts "Error: Path '#{path}' does not exist"
    exit 1
  end

  format_files(path)
end
