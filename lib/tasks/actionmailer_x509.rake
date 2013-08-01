require 'rake'
require 'rake/testtask'
require 'rdoc/task'
require 'models/notifier'
require 'actionmailer_x509/x509'


namespace :actionmailer_x509 do
  task :all do
    Rake.application.in_namespace(:actionmailer_x509) do |x|
      x.tasks.each do |task|
        unless task.to_s == 'actionmailer_x509:all'
          Rake::Task[task].invoke
        end
      end
    end
  end

  desc "Sending a mail that can be signed and\\or crypted, for test."
  task(:send_test => :environment) do
    email = ENV['email']
    if email.nil?
      puts "You should call the rake task like\nrake actionmailer_x509:send_test email=yourmail@yourdomain.com signed=true crypted=false\n"
    else
      puts "Note: Please make sure you have configured ActionMailer."
      puts "The mail sent might be stoped by antispam."
      puts "If you wish to verify the signature, please include"
      puts "#{File.dirname(__FILE__)}/../certs/ca.crt"
      puts "as an authority in your MUA. Remove it after your test!!!\n\n"
      puts "Emailing <#{email}>"

      signed = if ENV['signed']
        Boolean(ENV['signed'])
      end || false
      crypted = Boolean(ENV['crypted'])

      noty = Notifier.fufu_signed_and_or_crypted(email, 'demo@foobar.com', "Signed mail at #{Time.now.to_s}", {:signed => signed, :crypted => crypted})
      noty.deliver
    end
  end

  desc 'Generates a signed mail in a file.'
  task(:generate_signed_mail => :environment) do
    mail = Notifier.fufu_signed('<destination@foobar.com>', '<demo@foobar.com>')
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
    mail = Notifier.fufu_signed('<destination@foobar.com>', '<demo@foobar.com>')
    raw_mail = Notifier.fufu_signed_and_or_crypted('<destination@foobar.com>', '<demo@foobar.com>', 'Empty subject', { signed: false, crypted: false })

    verified = mail.proceed(Notifier.x509)

    #puts '*' * 100
    #puts set_format(raw_mail.body.to_s)
    #puts '*' * 100
    #puts set_format(verified.to_s)
    #puts '*' * 100

    puts "Verification is #{set_format(verified.to_s) == set_format(raw_mail.body.to_s)}"
  end

  desc 'Check if signature is valid by openssl.'
  task(:verify_signature_by_openssl => :environment) do
    require 'tempfile'
    mail = Notifier.fufu_signed("<destination@foobar.com>", "<demo@foobar.com>")

    tf = Tempfile.new('actionmailer_x509')
    tf.write mail.encoded
    tf.flush

    comm = "openssl smime -verify -in #{tf.path} -CAfile #{build_path(Notifier.x509[:sign_cert])} > /dev/null"

    puts 'Using openssl command to verify signature...'
    system(comm)
  end

  desc 'Generates a crypted mail in a file.'
  task(:generate_crypted_mail => :environment) do
    mail = Notifier.fufu_crypted('<destination@foobar.com>', '<demo@foobar.com>')
    path = ENV['mail'] || Rails.root.join('certs/cripted_mail.txt')

    File.open(path, 'wb') do |f|
      f.write mail.body
    end

    p "Crypted mail is at #{path}"
    p 'You can use mail=filename as argument to change it.' if ENV['mail'].nil?
  end

  desc 'Check crypt.'
  task(:verify_crypt => :environment) do
    require 'tempfile'
    mail = Notifier.fufu_crypted('<destination@foobar.com>', '<demo@foobar.com>')
    raw_mail = Notifier.fufu_signed_and_or_crypted('<destination@foobar.com>', '<demo@foobar.com>', 'Empty subject', { signed: false, crypted: false })

    decrypted = mail.proceed(Notifier.x509)

    #puts '*' * 100
    #puts raw_mail
    #puts '*' * 100
    #puts mail.encoded
    #puts '*' * 100
    #puts decrypted
    #puts '*' * 100

    puts "Crypt verification is #{set_format(decrypted.to_s) == set_format(raw_mail.body.to_s)}"
  end

  desc 'Check if crypt text is valid by openssl.'
  task(:verify_crypt_by_openssl => :environment) do
    require 'tempfile'
    mail = Notifier.fufu_crypted("<destination@foobar.com>", "<demo@foobar.com>")

    tf = Tempfile.new('actionmailer_x509')
    tf.write mail.encoded
    tf.flush

    comm = "openssl smime -decrypt -passin pass:#{Notifier.x509[:crypt_passphrase]} -in #{tf.path} -recip #{build_path(Notifier.x509[:crypt_cert])} -inkey #{build_path(Notifier.x509[:crypt_key])} > /dev/null"
    puts 'Using openssl command to verify crypted code...'
    puts "Crypt verification is #{system(comm)}"
  end

  desc 'Check sign and crypt.'
  task(:verify_sign_and_crypt => :environment) do
    require 'tempfile'
    mail = Notifier.fufu_signed_and_or_crypted('<destination@foobar.com>', '<demo@foobar.com>', 'Empty subject', { signed: true, crypted: true })
    raw_mail = Notifier.fufu_signed_and_or_crypted('<destination@foobar.com>', '<demo@foobar.com>', 'Empty subject', { signed: false, crypted: false })

    decrypted = mail.proceed(Notifier.x509)
    puts decrypted
    puts raw_mail.body

    puts "Verification is #{set_format(decrypted.to_s) == set_format(raw_mail.body.to_s)}"
  end

  desc 'Performance test.'
  task(:performance_test => :environment) do
    require 'benchmark'

    n = 100
    Benchmark.bm do |x|
      x.report("#{n} raw mails: ".ljust(40)) {
        n.times { Notifier.fufu('<destination@foobar.com>', '<demo@foobar.com>') }
      }
      x.report("#{n} mails with signature: ".ljust(40)) {
        n.times { Notifier.fufu_signed('<destination@foobar.com>', '<demo@foobar.com>') }
      }

      x.report("#{n} crypted mails: ".ljust(40)) {
        n.times { Notifier.fufu_crypted('<destination@foobar.com>', '<demo@foobar.com>') }
      }

      x.report("#{n} crypted and signed mails: ".ljust(40)) {
        n.times { Notifier.fufu_signed_and_crypted('<destination@foobar.com>', '<demo@foobar.com>') }
      }
    end
  end
end

private

def build_path(path)
  #"#{File.dirname(__FILE__)}/../../#{path}"
  path
end

def set_format(text)
  text.gsub("\r\n", "\n")
end

def Boolean(string)
  return true if string == true || string =~ /^true$/i
  return false if string == false || string.nil? || string =~ /^false$/i
  raise ArgumentError.new("invalid value for Boolean: \"#{string}\"")
end

