#!/usr/bin/env ruby
# frozen_string_literal: true

# rubocop:disable Metrics

# Script to update OCI CIS control files:
#   ruby update_controls.rb rename  — Rename files and control IDs, remove STIG tags
#   ruby update_controls.rb tags    — Fix CCI/NIST tags, add CIS-specific tags

require 'json'
require 'fileutils'

CONTROLS_DIR = File.join(__dir__, 'controls')
BENCHMARK_JSON = File.join(__dir__, 'cis_oracle_cloud_infrastructure_foundations_benchmark_v300.json')
CCI_MAPPING_JSON = File.join(__dir__, 'cis-cci-mapping.json')

STIG_TAGS = %w[check_id gid rid stig_id gtitle].freeze
STIG_STANDALONE_TAGS = %w[documentable].freeze

# Convert underscore filename to dotted OCI ref: 1_1 → 1.1, 5_1_3 → 5.1.3
def filename_to_ref(basename)
  basename.sub(/\.rb$/, '').gsub('_', '.')
end

# Convert new-style filename to OCI ref: oci-foundations-1.1.rb → 1.1
def new_filename_to_ref(basename)
  basename.sub(/^oci-foundations-/, '').sub(/\.rb$/, '')
end

# ─── RENAME MODE ──────────────────────────────────────────────────────────────

def run_rename
  files = Dir.glob(File.join(CONTROLS_DIR, '*.rb')).sort
  puts "Found #{files.length} control files to rename\n\n"

  files.each do |old_path|
    basename = File.basename(old_path)

    # Skip already-renamed files
    if basename.start_with?('oci-foundations-')
      puts "  SKIP #{basename} (already renamed)"
      next
    end

    ref = filename_to_ref(basename)
    new_basename = "oci-foundations-#{ref}.rb"
    new_path = File.join(CONTROLS_DIR, new_basename)

    content = File.read(old_path)
    new_content = rename_content(content, ref)

    File.write(new_path, new_content)
    File.delete(old_path)
    puts "  #{basename} → #{new_basename}"
  end

  puts "\nDone. Run 'git diff --stat' to verify renames."
end

def rename_content(content, ref)
  lines = content.lines
  result = []

  lines.each do |line|
    # Replace control ID line (handle both single and double quotes)
    if line =~ /\A(\s*)control\s+["'].*?["']\s+do/
      result << "#{Regexp.last_match(1)}control 'oci-foundations-#{ref}' do\n"
      next
    end

    # Remove STIG-specific key:value tags
    next if line =~ /\A\s*tag\s+(#{STIG_TAGS.join('|')}):/

    # Remove standalone tag 'documentable'
    next if line =~ /\A\s*tag\s+['"]documentable['"]\s*$/

    # Remove blank lines left by removed tags (consecutive blanks will be cleaned later)
    result << line
  end

  # Clean up consecutive blank lines in the tag section
  clean_consecutive_blanks(result.join)
end

def clean_consecutive_blanks(content)
  content.gsub(/\n{3,}/, "\n\n")
end

# ─── TAGS MODE ────────────────────────────────────────────────────────────────

def run_tags
  benchmark = load_benchmark
  cci_map = load_cci_mapping

  files = Dir.glob(File.join(CONTROLS_DIR, 'oci-foundations-*.rb')).sort
  puts "Found #{files.length} control files to update tags\n\n"

  files.each do |path|
    basename = File.basename(path)
    ref = new_filename_to_ref(basename)
    rec = benchmark[ref]

    unless rec
      puts "  WARN: No benchmark entry for #{ref} (#{basename})"
      next
    end

    content = File.read(path)
    new_content = update_tags(content, ref, rec, cci_map)
    File.write(path, new_content)
    puts "  Updated: #{basename}"
  end

  puts "\nDone. Run 'bundle exec rake pre_commit_checks' to verify."
end

def load_benchmark
  data = JSON.parse(File.read(BENCHMARK_JSON))
  map = {}
  data['recommendations'].each do |rec|
    ref = rec['ref']
    v8_controls = rec.fetch('cis_controls', [])
                     .select { |c| c['version'] == 8 }
                     .map { |c| c['control'].to_s }
    level = rec.fetch('profiles', []).first || 'Level 1'
    assessment = rec.fetch('assessment_status', 'Manual')
    map[ref] = { v8_controls: v8_controls, cis_level: level, assessment_status: assessment }
  end
  map
end

def load_cci_mapping
  data = JSON.parse(File.read(CCI_MAPPING_JSON))
  map = {}
  data.each do |entry|
    map[entry['cis_id']] = {
      cci: entry.dig('primary_cci', 'cci'),
      nist: entry['nist_control']
    }
  end
  map
end

def update_tags(content, ref, rec, cci_map)
  v8_controls = rec[:v8_controls]
  cis_level = rec[:cis_level]
  assessment_status = rec[:assessment_status]

  # Collect primary CCIs and NIST controls from v8 control IDs
  ccis = []
  nists = []
  v8_controls.each do |v8_id|
    next if v8_id == '0.0' # Explicitly not mapped

    mapping = cci_map[v8_id]
    if mapping
      ccis << mapping[:cci] if mapping[:cci]
      nists << mapping[:nist] if mapping[:nist]
    else
      puts "    WARN: CIS v8 ID '#{v8_id}' not found in CCI mapping (ref #{ref})"
    end
  end
  ccis.uniq!
  nists.uniq!

  # Build new tag block
  lines = content.lines
  result = []
  in_tag_section = false
  tag_section_started = false
  tags_written = false
  skip_until_closing_bracket = false

  lines.each do |line|
    # Detect start of tag section (first tag line after impact)
    if !tag_section_started && line =~ /\A\s*tag\s+/
      tag_section_started = true
      in_tag_section = true
    end

    # Handle multi-line CCI/NIST arrays (skip old tag content)
    if skip_until_closing_bracket
      skip_until_closing_bracket = false if line.strip == ']'
      next
    end

    if in_tag_section
      # Detect end of tag section: a non-blank, non-tag line that isn't ]
      if line.strip != '' && line !~ /\A\s*tag\s+/ && line.strip != ']'
        # Write new tags before the code section
        unless tags_written
          write_new_tags(result, ref, cis_level, assessment_status, v8_controls, ccis, nists)
          tags_written = true
        end
        in_tag_section = false
        result << line
        next
      end

      # Skip all old tag lines (we'll rewrite them)
      if line =~ /\A\s*tag\s+/
        # Check if this starts a multi-line array
        skip_until_closing_bracket = true if line =~ /\A\s*tag\s+(cci|nist):\s*\[/ && !line.include?(']')
        next
      end

      # Skip blank lines in tag section (we'll add our own)
      next if line.strip == ''

      next
    end

    result << line
  end

  # If tag section was at the very end (before 'end'), write tags
  unless tags_written
    # Find the last 'end' and insert before it
    end_idx = result.rindex { |l| l.strip == 'end' }
    if end_idx
      tag_lines = []
      write_new_tags(tag_lines, ref, cis_level, assessment_status, v8_controls, ccis, nists)
      result.insert(end_idx, *tag_lines)
    end
  end

  clean_consecutive_blanks(result.join)
end

def write_new_tags(result, ref, cis_level, assessment_status, v8_controls, ccis, nists)
  result << "  tag severity: 'medium'\n"
  result << "  tag benchmark_ref: '#{ref}'\n"
  result << "  tag cis_level: '#{cis_level}'\n"
  result << "  tag assessment_status: '#{assessment_status}'\n"

  if v8_controls.any?
    result << if v8_controls.length == 1
                "  tag cis_controls: %w[#{v8_controls.first}]\n"
              else
                "  tag cis_controls: %w[#{v8_controls.join(' ')}]\n"
              end
  end

  result << "\n"

  result << if ccis.any?
              "  tag cci: %w[#{ccis.join(' ')}]\n"
            else
              "  tag cci: []\n"
            end

  result << "\n"

  if nists.any?
    nist_items = nists.map { |n| "'#{n}'" }.join(', ')
    result << "  tag nist: [#{nist_items}]\n"
  else
    result << "  tag nist: []\n"
  end

  result << "\n"
end

# ─── MAIN ─────────────────────────────────────────────────────────────────────

mode = ARGV[0]

case mode
when 'rename'
  run_rename
when 'tags'
  run_tags
else
  puts 'Usage: ruby update_controls.rb [rename|tags]'
  puts '  rename  — Rename files + control IDs, remove STIG tags'
  puts '  tags    — Fix CCI/NIST, add CIS-specific tags'
  exit 1
end
# rubocop:enable Metrics
