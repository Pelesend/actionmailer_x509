require 'rubygems'
require 'test/unit'
require 'helper'
require_relative '../init'

class ActionmailerX509Test < Test::Unit::TestCase #:nodoc:
  # If we want to encrypt a message, verify a signature is attached
  def test_signed_and_crypted
    root = File.dirname(File.expand_path(__FILE__)) + '/../' + 'lib/certs/'
    @server_crt = "#{root}server.crt"
    @server_key = "#{root}server.key"
    @ca_file = "#{root}ca.crt"

    mail = Notifier.fufu_signed_and_crypted("<destination@foobar.com>", "<demo@foobar.com>")

    assert_contains "x-pkcs7-signature", mail.content_type

    require 'tempfile'

    tf = Tempfile.new('actionmailer_x509')
    tf.write mail.encoded
    tf.flush
    
    comm = "openssl smime -decrypt -in #{tf.path} -recip #{@server_crt} -inkey #{@server_key} -passin pass:demo | openssl smime -verify -CAfile #{@ca_file} 2>&1"
   
    success = false
    output = IO.popen(comm)
    while output.gets do
      if $_ =~ /^Verification successful/
        success = true
      end
    end
    assert success, 'Verification failed'
  end

  # If we want to encrypt a message, verify a signature is attached
  def test_crypted
    mail = Notifier.fufu_crypted("<destination@foobar.com>", "<demo@foobar.com>")

    assert_equal mail.delivery_method.settings[:address], 'smtp.com'
    assert_equal mail.from, [ "demo@foobar.com" ]

    require 'tempfile'

    tf = Tempfile.new('actionmailer_x509')
    tf.write mail.encoded
    tf.flush

    comm = "openssl smime -decrypt -in #{tf.path} -recip #{@server_crt} -inkey #{@server_key} -passin pass:demo 2>&1"

    success = false
    output = IO.popen(comm)
    while output.gets do
      if $_ =~ /^This is the 3rd line, to make sure.../
      #unless $_ =~ /^Error reading S\/MIME message/
        success = true
      end
    end
    assert success, 'Verification failed'
  end


  # # If we want to sign a message, verify a signature is attached
  # def test_signed
  #   mail = Notifier.fufu_signed("<destination@foobar.com>", "<demo@foobar.com>")

  #   assert_equal mail.delivery_method.settings[:address], 'smtp.com'
  #   assert_equal mail.from, [ "demo@foobar.com" ]

  #   found = false
  #   for part in mail.parts do
  #     if part.content_type =~ /application\/x-pkcs7-signature/
  #       found = true
  #       break
  #     end
  #   end
  #   assert_equal found, true

  #   require 'tempfile'

  #   tf = Tempfile.new('actionmailer_x509')
  #   tf.write mail.encoded
  #   tf.flush

  #   comm = "cd #{@root}; openssl smime -verify -in #{tf.path} -CAfile #{@ca_file} 2>&1"

  #   success = false
  #   output = IO.popen(comm)
  #   while output.gets do
  #     if $_ =~ /^Verification successful/
  #       success = true
  #     end
  #   end
  #   assert_equal(success, true)
  # end

  # # If we want no signature, verify not signature is attached to the mail
  # def test_not_signed
  #   mail = Notifier.fufu("<destination@foobar.com>", "<demo@foobar.com>")

  #   found = false
  #   for part in mail.parts do
  #     puts part.content_type
  #     if part.content_type =~ /application\/x-pkcs7-signature/
  #       found = true
  #       break
  #     end
  #   end
  #   assert_equal found, false
  # end

  # # If we want to sign a message but no certificate is on the filesystem
  # def test_signed_with_no_certs
  #   crashed = false
  #   begin
  #     mail = Notifier.fufu_signed("<destination@foobar.com>", "<demo@foobar.com>", "", "/tmp/doesnotexist")
  #   rescue Errno::ENOENT => detail
  #     crashed = true
  #   end

  #   assert_equal(crashed, true)
  # end

  # # If we want to sign a message but incorrect certificate is given
  # def test_signed_incorrect_certs
  #   crashed = false
  #   begin
  #     mail = Notifier.fufu_signed("<destination@foobar.com>", "<demo@foobar.com>", "", @server_key)
  #   rescue OpenSSL::X509::CertificateError => detail
  #     crashed = true
  #   end
  #   assert_equal(crashed, true)
  # end
end
