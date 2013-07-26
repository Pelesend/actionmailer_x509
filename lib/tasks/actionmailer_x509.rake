require 'rake'
require 'rake/testtask'
require 'rdoc/task'
require 'models/notifier'
require 'actionmailer_x509/x509'


namespace :actionmailer_x509 do
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

      noty = Notifier.fufu_signed_and_or_crypted(email, "demo@foobar.com", "Signed mail at #{Time.now.to_s}", {:signed => signed, :crypted => crypted})
      noty.deliver
    end
  end

  desc "Generates a signed mail in a file."
  task(:generate_signed_mail => :environment) do
    mail = Notifier.fufu_signed("<destination@foobar.com>", "<demo@foobar.com>")
    path = ENV['mail']
    path = "tmp/signed_mail.txt" if path.nil?
    File.open(path, "w") do |f|
      f.write mail.body
    end
    puts "Signed mail is at #{path}."
    puts "You can use mail=filename as argument to change it." if ENV['mail'].nil?
  end

  desc "Check if signature is valid."
  task(:verify_signature => :environment) do
    require 'tempfile'
    mail = Notifier.fufu_signed("<destination@foobar.com>", "<demo@foobar.com>")

    coded = ActionMailerX509::X509.new(
        Notifier.x509[:crypt_cert],
        Notifier.x509[:crypt_key],
        Notifier.x509[:crypt_passphrase],
        Notifier.x509[:crypt_cipher]).decode(mail.encoded)

    puts "Verifycation is #{coded == Notifier.fufu_signed("<destination@foobar.com>", "<demo@foobar.com>").encoded}"


    #tf = Tempfile.new('actionmailer_x509')
    #tf.write mail.encoded
    #tf.flush

    #comm = "openssl smime -verify -in #{tf.path} -CAfile #{File.dirname(__FILE__)}/../certs/ca.crt > /dev/null"
    #
    #puts "Using openssl command to verify signature..."
    #system(comm)
  end

  desc "Generates a crypted mail in a file."
  task(:generate_crypted_mail => :environment) do
    mail = Notifier.fufu_crypted("<destination@foobar.com>", "<demo@foobar.com>")
    path = ENV['mail']
    path = "tmp/signed_mail.txt" if path.nil?
    File.open(path, "w") do |f|
      f.write mail.body
    end
    puts "Crypted mail is at #{path}."
    puts "You can use mail=filename as argument to change it." if ENV['mail'].nil?
  end

  desc "Performance test."
  task(:performance_test => :environment) do
    require 'benchmark'

    n = 100
    Benchmark.bm do |x|
      x.report("#{n} mails without signature: ") {
        for i in 1..n do
          Notifier.fufu("<destination@foobar.com>", "<demo@foobar.com>")
        end
      }
      x.report("#{n} mails with signature: ") {
        for i in 1..n do
          Notifier.fufu_signed("<destination@foobar.com>", "<demo@foobar.com>")
        end
      }
    end
  end
end

private

def Boolean(string)
  return true if string == true || string =~ /^true$/i
  return false if string == false || string.nil? || string =~ /^false$/i
  raise ArgumentError.new("invalid value for Boolean: \"#{string}\"")
end

