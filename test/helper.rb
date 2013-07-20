require 'test/unit'

unless defined?(ActiveRecord)
  plugin_root = File.join(File.dirname(__FILE__), '..')

  # first look for a symlink to a copy of the framework
  if framework_root = ["#{plugin_root}/rails", "#{plugin_root}/../../rails"].find { |p| File.directory? p }
    puts "found framework root: #{framework_root}"
    # this allows for a plugin to be tested outside an app
    $:.unshift "#{framework_root}/activesupport/lib", "#{framework_root}/activerecord/lib", "#{framework_root}/actionpack/lib"
  else
    # is the plugin installed in an application?
    app_root = plugin_root + '/../../..'

    if File.directory? app_root + '/config'
      puts 'using config/boot.rb'
      ENV['RAILS_ENV'] = 'test'
      require File.expand_path(app_root + '/config/boot')
    else
      # simply use installed gems if available
      puts 'using rubygems'
      require 'rubygems'
      gem 'actionpack'; gem 'activerecord'
    end
  end

   require 'action_mailer'

#  ActiveSupport::Dependencies.autoload_paths.unshift "#{plugin_root}/lib"
   require plugin_root + '/lib/models/notifier'
end

ActionMailer::Base.smtp_settings = {
    :address => "smtp.com",
    :port => 465,
    :domain => 'test.com',
    :user_name => 'user',
    :password => 'pass',
    :authentication => 'login',
    :enable_starttls_auto => true
}

module Test::Unit::Assertions
  def assert_contains(expected_substring, string, *args)
    assert string.include?(expected_substring), 'not includes given substring'
  end
end

