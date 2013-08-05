require 'actionmailer_x509'
class Notifier < ActionMailer::Base #:nodoc:
  x509_configuration :test
  self.prepend_view_path("#{File.dirname(__FILE__)}/../views/")

  def fufu(email, from, subject = 'Empty subject')
    mail(subject: subject, to: email, from: from) do |format|
      format.text { render 'fufu' }
    end
  end
end
