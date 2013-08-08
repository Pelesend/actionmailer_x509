require 'rake'
require 'rake/testtask'
require 'rdoc/task'
require 'models/notifier'
require 'actionmailer_x509/x509'

namespace :actionmailer_x509 do
  desc 'Run all checks'
  task :all do
    puts '*' * 20 << 'SIGN VERIFICATION'
    Rake::Task['actionmailer_x509:verify_signature'].invoke
    puts '*' * 20 << 'OPENSSL SIGN VERIFICATION'
    Rake::Task['actionmailer_x509:verify_signature_by_openssl'].invoke
    puts '*' * 20 << 'CRYPT VERIFICATION'
    Rake::Task['actionmailer_x509:verify_crypt'].invoke
    puts '*' * 20 << 'OPENSSL CRYPT VERIFICATION'
    Rake::Task['actionmailer_x509:verify_crypt_by_openssl'].invoke
    puts '*' * 20 << 'SIGN AND CRYPT VERIFICATION'
    Rake::Task['actionmailer_x509:verify_sign_and_crypt'].invoke
    puts '*' * 20
  end

  desc 'Generates a signed mail in a file.'
  task(:generate_signed_mail => :environment) do
    add_config(true, false)
    mail = Notifier.fufu('<destination@foobar.com>', '<demo@foobar.com>')
    path = ENV['mail'] || Rails.root.join('certs/signed_mail.txt')
    File.open(path, 'wb') do |f|
      f.write mail.body
    end
    puts "Signed mail is at #{path}"
    puts 'You can use mail=filename as argument to change it.' if ENV['mail'].nil?
  end

  desc 'Check if signature is valid.'
  task(:verify_signature => :environment) do
    require 'tempfile'
    add_config(false, false)
    raw_mail = Notifier.fufu('<destination@foobar.com>', '<demo@foobar.com>')

    add_config(true, false)
    mail = Notifier.fufu('<destination@foobar.com>', '<demo@foobar.com>')

    verified = mail.proceed(Notifier.x509_configuration)
    puts "Verification is #{verified.to_s == raw_mail.content}"
  end

  desc 'Check if signature is valid by openssl.'
  task(:verify_signature_by_openssl => :environment) do
    require 'tempfile'

    add_config(true, false)
    mail = Notifier.fufu("<destination@foobar.com>", "<demo@foobar.com>")

    tf = Tempfile.new('actionmailer_x509')
    tf.write mail.encoded
    tf.flush
    configuration = ActionMailerX509.get_configuration(Notifier.x509_configuration)

    comm = "openssl smime -verify -in #{tf.path} -CAfile #{configuration.sign_cert} > /dev/null"

    puts 'Using openssl command to verify signature...'
    system(comm)
  end

  desc 'Generates a crypted mail in a file.'
  task(:generate_crypted_mail => :environment) do
    add_config(false, true)
    mail = Notifier.fufu('<destination@foobar.com>', '<demo@foobar.com>')
    path = ENV['mail'] || Rails.root.join('certs/cripted_mail.txt')

    File.open(path, 'wb') do |f|
      f.write mail.body
    end

    p "Crypted mail is at #{path}"
    p 'You can use mail=filename as argument to change it.' if ENV['mail'].nil?
  end

  desc 'Check crypt.'
  task(:verify_crypt => :environment) do
    add_config(false, false)
    raw_mail = Notifier.fufu('<destination@foobar.com>', '<demo@foobar.com>')

    add_config(false, true)
    mail = Notifier.fufu('<destination@foobar.com>', '<demo@foobar.com>')

    decrypted = mail.proceed(Notifier.x509_configuration)
    puts "Crypt verification is #{decrypted.to_s == raw_mail.content}"
  end

  desc 'Check if crypt text is valid by openssl.'
  task(:verify_crypt_by_openssl => :environment) do
    require 'tempfile'

    add_config(false, true)
    mail = Notifier.fufu("<destination@foobar.com>", "<demo@foobar.com>")

    tf = Tempfile.new('actionmailer_x509')
    tf.write mail.encoded
    tf.flush
    configuration = ActionMailerX509.get_configuration(Notifier.x509_configuration)

    comm = "openssl smime -decrypt -passin pass:#{configuration.crypt_passphrase} -in #{tf.path} -recip #{configuration.crypt_cert} -inkey #{configuration.crypt_key} > /dev/null"
    puts 'Using openssl command to verify crypted code...'
    puts "Crypt verification is #{system(comm)}"
  end

  desc 'Check sign and crypt.'
  task(:verify_sign_and_crypt => :environment) do
    add_config(false, false)
    raw_mail = Notifier.fufu('<destination@foobar.com>', '<demo@foobar.com>')

    add_config
    mail = Notifier.fufu('<destination@foobar.com>', '<demo@foobar.com>')

    decrypted = mail.proceed(Notifier.x509_configuration)
    puts "Verification is #{decrypted.to_s == raw_mail.content}"
  end

  desc 'Performance test.'
  task(:performance_test => :environment) do
    require 'benchmark'

    n = 100
    Benchmark.bm do |x|
      add_config(false, false)
      x.report("#{n} raw mails: ".ljust(40)) {
        n.times { Notifier.fufu('<destination@foobar.com>', '<demo@foobar.com>') }
      }
      add_config(true)
      x.report("#{n} mails with signature: ".ljust(40)) {
        n.times { Notifier.fufu_signed('<destination@foobar.com>', '<demo@foobar.com>') }
      }

      add_config(false, true)
      x.report("#{n} crypted mails: ".ljust(40)) {
        n.times { Notifier.fufu_crypted('<destination@foobar.com>', '<demo@foobar.com>') }
      }

      add_config
      x.report("#{n} crypted and signed mails: ".ljust(40)) {
        n.times { Notifier.fufu_signed_and_crypted('<destination@foobar.com>', '<demo@foobar.com>') }
      }
    end
  end
end

private
def add_config(sign = true, crypt = true)
  ActionMailerX509.add_configuration :test,
                           {
                               sign_enable: sign,
                               crypt_enable: crypt,
                               sign_cert: 'ca.crt',
                               sign_key: 'ca.key',
                               sign_passphrase: 'hisp',
                               crypt_cert: 'ca.crt',
                               crypt_key: 'ca.key',
                               crypt_passphrase: 'hisp',
                               certs_path: Rails.root.join('certs')
                           }
end

def Boolean(string)
  return true if string == true || string =~ /^true$/i
  return false if string == false || string.nil? || string =~ /^false$/i
  raise ArgumentError.new("invalid value for Boolean: \"#{string}\"")
end

